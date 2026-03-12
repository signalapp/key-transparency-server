//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//go:generate protoc -I ./pb -I ../../tree/transparency/pb --go_out=pb --go_opt=paths=source_relative --go-grpc_out=pb --go-grpc_opt=paths=source_relative key_transparency.proto key_transparency_query.proto key_transparency_test.proto

// Command kt-server is the main server process that answers all client
// requests and sequences new changes to the log.
package main

import (
	"context"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/db"
)

var (
	Version   = "dev"
	GoVersion = runtime.Version()

	configFile = flag.String("config", "", "Location of config file.")
	liveness   = "liveness"
	readiness  = "readiness"
)

func main() {
	flag.Parse()
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGTERM)

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}

	// Load config from disk.
	if *configFile == "" {
		logger := zerolog.New(consoleWriter).With().Timestamp().Logger()
		logger.Fatal().Msg("no config file specified")
	}
	config, err := config.Read(*configFile)
	if err != nil {
		logger := zerolog.New(consoleWriter).With().Timestamp().Logger()
		logger.Fatal().Msgf("failed to parse config file: %v", err)
	}

	var zeroLogLogger zerolog.Logger
	var logWriter io.Writer
	if len(config.LogOutputFile) > 0 {
		logWriter = zerolog.MultiLevelWriter(
			consoleWriter,
			&lumberjack.Logger{
				Filename:   config.LogOutputFile,
				MaxBackups: 10,
				Compress:   true,
			},
		)
		zeroLogLogger = zerolog.New(logWriter).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	} else {
		logWriter = consoleWriter
		zeroLogLogger = zerolog.New(logWriter).With().Caller().Timestamp().Logger()
	}
	util.SetLoggerInstance(&zeroLogLogger)

	// Register healthCheck service
	healthServer := grpc.NewServer()
	healthCheck := health.NewServer()
	healthgrpc.RegisterHealthServer(healthServer, healthCheck)

	// Initialize liveness and readiness states
	healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_SERVING)
	healthCheck.SetServingStatus(readiness, healthpb.HealthCheckResponse_NOT_SERVING)

	// Configure healthCheck service to listen on its dedicated port
	lis, err := net.Listen("tcp", config.HealthAddr)
	if err != nil {
		util.Log().Fatalf("failed to listen on health check port %v: %v", config.HealthAddr, err)
	}
	util.Log().Infof("Starting health check server at: %v", config.HealthAddr)

	// Start the health server.
	go healthServer.Serve(lis)

	// Start the metrics server.
	exportMetrics(ctx, config.OtlpEnabled)
	go metricsServer(config.MetricsAddr)

	// Start the inserter thread.
	tx, err := config.DatabaseConfig.Connect()
	if err != nil {
		healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
		util.Log().Fatalf("Failed to connect to database: %v", err)
	}

	// Is this a new, empty tree?
	first := false
	if tth, _, err := tx.GetHead(); err != nil {
		healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
		util.Log().Fatalf("unable to get transparency tree head: %v", err)
	} else {
		util.Log().Infof("Tree size: %d", tth.TreeSize)
		first = tth.TreeSize == 0
	}

	// This is the read-only service.
	// For now, it always queries the database directly and does not use a cache.
	if config.KtQueryServiceConfig != nil {
		// For read-only servers, cache immutable data.
		// The log tree data is only cached when the chunk is full (and therefore immutable).
		queryCachedTransparencyStore := db.NewCachedTransparencyStore(tx, db.TransparencyCache|db.PrefixCache|db.LogCache, config.CacheConfig.TopSize, config.CacheConfig.LogSize, config.CacheConfig.PrefixSize)

		// Connect to the account DB
		accountDB, err := config.ConnectAccountDB()
		ktQueryHandler := &KtQueryHandler{config: config.APIConfig, tx: queryCachedTransparencyStore.Clone(), accountDB: accountDB}

		// Create listener for specified port
		ktQueryListener, err := createListener(config.KtQueryServiceConfig)

		if err != nil {
			healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
			util.Log().Fatalf("Failed to create listener for kt query server: %v", err)
		}

		// Register kt query server
		ktQueryServer := grpc.NewServer(getServerOptions(config.KtQueryServiceConfig, nil)...)
		pb.RegisterKeyTransparencyQueryServiceServer(ktQueryServer, ktQueryHandler)

		util.Log().Infof("Starting kt-query server at: %v", config.KtQueryServiceConfig.ServerAddr)
		if config.KtServiceConfig == nil && config.KtTestServiceConfig == nil {
			healthCheck.SetServingStatus(readiness, healthpb.HealthCheckResponse_SERVING)
			ktQueryServer.Serve(ktQueryListener)
		} else {
			go ktQueryServer.Serve(ktQueryListener)
		}
	}

	ch := make(chan updateRequest)
	auditorTreeHeadsCh := make(chan updateAuditorTreeHeadRequest)

	// Cache all data for the service that handles writes
	cachedTransparencyStore := db.NewCachedTransparencyStore(tx, db.TransparencyCache|db.PrefixCache|db.LogCache|db.HeadCache, config.CacheConfig.TopSize, config.CacheConfig.LogSize, config.CacheConfig.PrefixSize)

	// Define a handler that provides a common interface for:
	// - stream-based updates
	// - distinguished updates
	// - manual updates from local testing
	// Its update functionality will only ever be exposed externally in a local development/testing context.
	updateHandler := &KtUpdateHandler{config: config.APIConfig, tx: cachedTransparencyStore.Clone(), ch: ch}

	if config.KtServiceConfig != nil || config.KtTestServiceConfig != nil {
		updaterTree, err := config.APIConfig.NewTree(cachedTransparencyStore)
		if err != nil {
			healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
			util.Log().Fatalf("failed to initialize tree: %v", err)
		}
		// Start updater goroutine
		go updater(updaterTree, ch, auditorTreeHeadsCh, config.APIConfig.FakeUpdates)

		// Start a goroutine that regularly updates a distinguished key
		if config.APIConfig.Distinguished != 0 {
			util.Log().Infof("Distinguished key will be maintained: %v", config.APIConfig.Distinguished)
			go distinguished(updateHandler, config.APIConfig.Distinguished)
		}
	}

	// This is the read and write service
	if config.KtServiceConfig != nil {
		// Start scanning a Kinesis stream, if one is provided.
		if config.StreamConfig != nil {
			s := &Streamer{config: config.APIConfig, tx: cachedTransparencyStore.Clone()}
			go func() {

				var backfillStreamStartTimestamp *time.Time

				if first && config.StreamConfig.TableName != "" {
					// start the stream from when the backfill started, minus some padding for clock drift
					start := time.Now().Add(-time.Minute * 15)
					backfillStreamStartTimestamp = &start

					util.Log().Infof("Backfilling from DynamoDB table %q", config.StreamConfig.TableName)
					if err := backfill(ctx, config.StreamConfig.TableName.String(), updateHandler); err != nil {
						healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
						util.Log().Fatalf("stream backfill failed: %v", err)
					}
				}

				for streamName, updateFromStreamFunc := range map[string]updateFunc{
					config.StreamConfig.AciStreamName.String():      updateFromAciStream,
					config.StreamConfig.E164StreamName.String():     updateFromE164Stream,
					config.StreamConfig.UsernameStreamName.String(): updateFromUsernameStream,
				} {
					var streamStartTimestamp *time.Time
					if backfillStreamStartTimestamp != nil {
						streamStartTimestamp = backfillStreamStartTimestamp
					} else {
						if slices.Contains(config.StreamConfig.NewStreams, streamName) {
							start := time.Now().Add(-time.Minute * 15)
							streamStartTimestamp = &start
						}
					}

					util.Log().Infof("Starting stream processing from Kinesis stream: %s", streamName)
					if streamStartTimestamp != nil {
						util.Log().Infof("%s stream start timestamp: %s", streamName, streamStartTimestamp.Format(time.RFC3339))
					}
					go func() {
						s.run(ctx, streamName, streamStartTimestamp, updateHandler, updateFromStreamFunc)
					}()
				}

			}()
		}

		ktHandler := &KtHandler{config: config.APIConfig, tx: cachedTransparencyStore.Clone(), ch: ch, auditorTreeHeadsCh: auditorTreeHeadsCh}
		ktServiceConfig := config.KtServiceConfig

		// Create listener on the specified port
		ktListener, err := createListener(ktServiceConfig)

		if err != nil {
			healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
			util.Log().Fatalf("Failed to create listener for kt server: %v", err)
		}

		ktServer := grpc.NewServer(getServerOptions(config.KtServiceConfig, []grpc.UnaryServerInterceptor{
			// Downstream interceptors expect the auditor name to be stored in the context, so this interceptor must
			// be listed first.
			storeAuditorNameInterceptor(config.KtServiceConfig),
			grpcServiceNameMetricsInterceptor()})...)
		pb.RegisterKeyTransparencyServiceServer(ktServer, ktHandler)
		pb.RegisterKeyTransparencyAuditorServiceServer(ktServer, ktHandler)

		util.Log().Infof("Starting kt server at: %v", ktServiceConfig.ServerAddr)
		if config.KtTestServiceConfig == nil {
			healthCheck.SetServingStatus(readiness, healthpb.HealthCheckResponse_SERVING)
			ktServer.Serve(ktListener)
		} else {
			go ktServer.Serve(ktListener)
		}
	}

	// This is a service for local development.
	// For testing purposes, it exposes an endpoint for manual updates.
	if config.KtTestServiceConfig != nil {
		util.Log().Warnf("Test service config found. This should only be configured in a development environment.")
		ktTestServiceConfig := config.KtTestServiceConfig

		// Create listener on the specified port
		ktTestListener, err := createListener(ktTestServiceConfig)

		if err != nil {
			healthCheck.SetServingStatus(liveness, healthpb.HealthCheckResponse_NOT_SERVING)
			util.Log().Fatalf("Failed to create listener for kt test server: %v", err)
		}

		ktTestServer := grpc.NewServer(getServerOptions(config.KtTestServiceConfig, nil)...)
		pb.RegisterKeyTransparencyTestServiceServer(ktTestServer, updateHandler)
		util.Log().Infof("Starting kt test server at: %v", ktTestServiceConfig.ServerAddr)
		healthCheck.SetServingStatus(readiness, healthpb.HealthCheckResponse_SERVING)
		ktTestServer.Serve(ktTestListener)
	}
}

func createListener(serviceConfig *config.ServiceConfig) (net.Listener, error) {
	return net.Listen("tcp", serviceConfig.ServerAddr)
}
