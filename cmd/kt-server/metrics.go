//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"

	metrics "github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/internal/util"
	ktmetrics "github.com/signalapp/keytransparency/cmd/kt-server/metrics"
	commonerrors "github.com/signalapp/keytransparency/common-errors"
	"github.com/signalapp/keytransparency/tree"
)

func successLabel(err error) metrics.Label {
	return metrics.Label{Name: "success", Value: fmt.Sprint(err == nil)}
}

func auditorLabel(auditorName string) metrics.Label {
	return metrics.Label{Name: "auditor", Value: auditorName}
}

func grpcStatusLabel(err error) metrics.Label {
	grpcError, _ := status.FromError(err)
	return metrics.Label{Name: "grpcStatus", Value: grpcError.Code().String()}
}

func outcomeLabel(err error) metrics.Label {
	var invalidArg *commonerrors.ErrInvalidArgument
	var invalidTreeConfiguration *tree.ErrInvalidTreeConfiguration
	var permissionDenied *commonerrors.ErrPermissionDenied

	var outcome string
	switch {
	case err == nil:
		outcome = "success"
	case errors.As(err, &invalidArg):
		outcome = "invalid_arg"
	case errors.As(err, &invalidTreeConfiguration):
		outcome = "invalid_tree_configuration"
	case errors.Is(err, tree.ErrEmptyTree):
		outcome = "empty_tree"
	case errors.Is(err, tree.ErrNotFound):
		outcome = "not_found"
	case errors.As(err, &permissionDenied):
		outcome = "permission_denied"
	case errors.Is(err, errInternal):
		outcome = "internal_error"
	default:
		outcome = "unknown_error"
	}
	return metrics.Label{Name: "outcome", Value: outcome}
}

func realLabel(real bool) metrics.Label {
	return metrics.Label{Name: "real", Value: fmt.Sprint(real)}
}

func tombstoneLabel(tombstone bool) metrics.Label {
	return metrics.Label{Name: "tombstone", Value: fmt.Sprint(tombstone)}
}

func endpointLabel(endpoint string) metrics.Label {
	return metrics.Label{Name: "endpoint", Value: endpoint}
}

func exportMetrics(ctx context.Context, otlpEnabled bool) {
	prom, err := prometheus.NewPrometheusSink()
	if err != nil {
		util.Log().Fatalf("building prometheus sink: %v", err)
	}
	sink := metrics.FanoutSink{prom}
	defer sink.Shutdown()

	if otlpEnabled {
		util.Log().Infof("Initiating otlp metrics")
		otlpSink, err := ktmetrics.NewOTLPSink(ctx)
		if err != nil {
			util.Log().Fatalf("error initializing otlp client: %v", err)
		}
		sink = append(sink, otlpSink)
	}

	// Disable hostname tagging, this can be provided by the downstream sink
	cfg := metrics.DefaultConfig("kt")
	cfg.EnableHostname = false
	cfg.EnableHostnameLabel = false
	if _, err = metrics.NewGlobal(cfg, sink); err != nil {
		util.Log().Fatalf("error initializing metrics : %v", err)
	}

	metrics.IncrCounterWithLabels([]string{"build_info"}, 1, []metrics.Label{
		{Name: "version", Value: Version},
		{Name: "goversion", Value: GoVersion},
	})
}

func metricsServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			fmt.Fprintln(rw, "Hi, I'm a key transparency metrics and debugging server!")
		} else {
			rw.WriteHeader(404)
			fmt.Fprintln(rw, "404 not found")
		}
	})
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/debug/version", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Version: %s, GoVersion: %s", Version, GoVersion)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	util.Log().Infof("Starting metrics server at: %v", addr)
	// go 1.24 requires a constant format string to Printf-like functions
	util.Log().Fatalf("%s", srv.ListenAndServe().Error())
}
