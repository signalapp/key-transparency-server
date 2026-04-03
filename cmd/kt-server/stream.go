//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	consumer "github.com/harlow/kinesis-consumer"
	metrics "github.com/hashicorp/go-metrics"
	"golang.org/x/sync/errgroup"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/transparency/pb"
)

const (
	backfillScanShards = 1000
	backfillWorkers    = 96
	withinBackfill     = "backfill"
	withinStream       = "stream"
	tombstoneString    = "tombstone"
)

var tombstoneBytes = marshalValue([]byte(tombstoneString))
var logUpdater = &LogUpdater{}

// metricsCounter implements the consumer.Counter interface for exporting
// Kinesis metrics.
type metricsCounter struct{}

func (pc metricsCounter) Add(name string, val int64) {
	metrics.IncrCounterWithLabels([]string{withinStream, "kinesis"}, float32(val), []metrics.Label{{Name: "type", Value: name}})
}

// kinesisLogger implements the consumer.Logger interface for printing Kinesis
// logs to stdout.
type kinesisLogger struct{}

func (kl kinesisLogger) Log(v ...any) { util.Log().Infof("%s", fmt.Sprintln(v...)) }

type Streamer struct {
	config *config.APIConfig
	tx     db.TransparencyStore
}

// run runs the streamer, blocking forever.
func (s *Streamer) run(ctx context.Context, name string, startAtTimestamp *time.Time, updateHandler *KtUpdateHandler,
	updateFunc updateFunc) {
	i := 0
	for {
		// Create a new context for each run.
		runCtx, cancel := context.WithCancel(ctx)

		opts := []consumer.Option{
			consumer.WithLogger(kinesisLogger{}),
			consumer.WithCounter(metricsCounter{}),
			consumer.WithStore(s.tx.StreamStore()),
		}
		if startAtTimestamp != nil {
			opts = append(opts,
				consumer.WithShardIteratorType(string(kinesistypes.ShardIteratorTypeAtTimestamp)),
				consumer.WithTimestamp(*startAtTimestamp))
		} else {
			opts = append(opts,
				consumer.WithShardIteratorType(string(kinesistypes.ShardIteratorTypeAfterSequenceNumber)))
		}

		c, err := consumer.New(name, opts...)
		if err != nil {
			util.Log().Errorf("%s stream consumer initialization error: %v", name, err)
			cancel()
			continue
		}
		startAtTimestamp = nil

		err = c.Scan(runCtx, func(r *consumer.Record) error {
			recordIteration := 0
			// Loop until we successfully process the record, or the context is closed.
			for {
				select {
				case <-runCtx.Done():
					return consumer.ErrSkipCheckpoint
				default:
					err := updateFunc(runCtx, dup(r.Data), updateHandler, logUpdater)
					if err != nil {
						metrics.IncrCounterWithLabels([]string{withinStream, "errors"}, 1,
							[]metrics.Label{{Name: "shardId", Value: r.ShardID}, {Name: "stream", Value: name}})
						// Cap backoff at 30 seconds
						sleep := time.Duration(math.Min(60, math.Pow(2, float64(recordIteration)))) * 500 * time.Millisecond
						util.Log().Warnf(
							"failed to update entry from stream: %v. streamName: %s, shardId: %s, seqNum: %s. iteration %d, sleeping %s.",
							err, name, r.ShardID, *r.SequenceNumber, recordIteration, sleep)
						select {
						case <-runCtx.Done():
							return consumer.ErrSkipCheckpoint
						case <-time.After(sleep):
						}
						recordIteration++
						continue
					}
					// Checkpoint after we finish processing each record
					return nil
				}
			}
		})

		if err != nil {
			util.Log().Errorf("%s stream scan error: %v", name, err)
		}

		// Clean up the current context in case we iterate again.
		cancel()

		// If the context is closed and c.Scan exited with no error, don't iterate. This handles
		// normal server shutdown behavior.
		if ctx.Err() != nil && err == nil {
			return
		}

		// Otherwise, sleep with exponential backoff (capped at 60 seconds).
		delay := time.Duration(math.Min(60, math.Pow(2, float64(i)))) * time.Second
		util.Log().Infof("iteration %d of %s stream consumer, sleeping %s", i, name, delay)
		time.Sleep(delay)

		i++
	}
}

func backfill(ctx context.Context, table string, updateHandler *KtUpdateHandler) error {
	eg, ctx := errgroup.WithContext(ctx)
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRetryer(func() aws.Retryer {
		// Max attempts set to 0 indicates that the attempt should be retried until it succeeds
		// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/retry#AdaptiveMode.MaxAttempts
		return retry.AddWithMaxAttempts(retry.NewAdaptiveMode(), 0)
	}))
	if err != nil {
		return fmt.Errorf("loading aws sdk config: %w", err)
	}
	ddb := dynamodb.NewFromConfig(cfg)
	totalShards := int32(backfillScanShards)
	eg.SetLimit(backfillWorkers)

	for shard := int32(0); shard < backfillScanShards; shard++ {
		shard := shard
		eg.Go(func() (returnedErr error) {
			util.Log().Infof("Starting processing of backfill shard %d", shard)
			defer func() {
				success := returnedErr == nil
				metrics.IncrCounterWithLabels([]string{withinBackfill, "shards_processed"}, 1,
					[]metrics.Label{{Name: "success", Value: strconv.FormatBool(success)}})
				if success {
					util.Log().Infof("Successfully finished processing backfill shard=%d", shard)
				} else {
					util.Log().Errorf("Failed to finish processing backfill shard=%d, err=%v ", shard, err)
				}
			}()
			var exclusiveStartKey map[string]types.AttributeValue
			for i := 0; ; i++ {
				if err := ctx.Err(); err != nil {
					return err
				}
				out, err := ddb.Scan(ctx, &dynamodb.ScanInput{
					TableName:         &table,
					Segment:           &shard,
					TotalSegments:     &totalShards,
					ExclusiveStartKey: exclusiveStartKey,
				})
				if err != nil {
					return fmt.Errorf("scan %d of shard %d failed: %w", i, shard, err)
				} else if err := backfillScanOutput(ctx, out, updateHandler, logUpdater); err != nil {
					return fmt.Errorf("scan %d of shard %d backfill processing failed: %w", i, shard, err)
				} else if exclusiveStartKey = out.LastEvaluatedKey; len(exclusiveStartKey) == 0 {
					return nil
				}
			}
		})
	}
	return eg.Wait()
}

func backfillScanOutput(ctx context.Context, scan *dynamodb.ScanOutput, updateHandler *KtUpdateHandler, updater Updater) error {
	for i, item := range scan.Items {
		if err := updateFromBackfill(ctx, item, updateHandler, updater); err != nil {
			metrics.IncrCounter([]string{withinBackfill, "accounts_processed", "error"}, 1)
			return fmt.Errorf("processing item %d: %w", i, err)
		}
		metrics.IncrCounter([]string{withinBackfill, "accounts_processed", "success"}, 1)
	}
	return nil
}

func updateFromBackfill(ctx context.Context, item map[string]types.AttributeValue, updateHandler *KtUpdateHandler, updater Updater) error {
	type backfillAccount struct {
		Number         string `json:"number"`
		ACIIdentityKey []byte `json:"identityKey"`
		UsernameHash   string `json:"usernameHash"` // URL-encoded base64
	}
	u := item["U"]
	if u == nil {
		return fmt.Errorf("no account ID")
	}
	ub, ok := u.(*types.AttributeValueMemberB)
	if !ok {
		util.Log().Errorf("account ID not bytes. %T %v", u, u)
		return fmt.Errorf("account ID not bytes")
	} else if len(ub.Value) != 16 {
		util.Log().Errorf("invalid account ID. account ID: %s",
			base64.StdEncoding.EncodeToString(ub.Value))
		return fmt.Errorf("account ID not valid")
	}
	accountID := ub.Value
	d := item["D"]
	if d == nil {
		util.Log().Errorf("account has no data. ACI: %s",
			base64.StdEncoding.EncodeToString(accountID))
		return fmt.Errorf("account %x no data", accountID)
	}
	db, ok := d.(*types.AttributeValueMemberB)
	if !ok {
		util.Log().Errorf("account data not bytes. ACI: %s",
			base64.StdEncoding.EncodeToString(accountID))
		return fmt.Errorf("account %x data not bytes", accountID)
	}
	var account backfillAccount
	if err := json.Unmarshal(db.Value, &account); err != nil {
		util.Log().Errorf("error parsing account data. ACI: %s, err: %v",
			base64.StdEncoding.EncodeToString(accountID), err)
		return fmt.Errorf("parsing account %x data: %w", accountID, err)
	} else if len(account.Number) == 0 {
		util.Log().Errorf("account has empty number. ACI: %s",
			base64.StdEncoding.EncodeToString(accountID))
		return fmt.Errorf("account %x data has empty number", accountID)
	}
	if len(account.ACIIdentityKey) > 0 {
		if err := updater.update(ctx, withinBackfill,
			append([]byte{shared.AciPrefix}, accountID...),
			marshalValue(account.ACIIdentityKey), updateHandler, nil); err != nil {
			util.Log().Errorf("error updating ACI. ACI: %s, ACI identity key: %s, err: %v",
				base64.StdEncoding.EncodeToString(accountID), base64.StdEncoding.EncodeToString(account.ACIIdentityKey), err)
			return fmt.Errorf("updating %x ACI: %w", accountID, err)
		}
	}
	if len(account.Number) > 0 {
		if err := updater.update(ctx, withinBackfill,
			append([]byte{shared.NumberPrefix}, []byte(account.Number)...),
			marshalValue(accountID), updateHandler, nil); err != nil {
			util.Log().Errorf("error updating number. ACI: %s, number: %s, err: %v",
				base64.StdEncoding.EncodeToString(accountID), account.Number, err)
			return fmt.Errorf("updating %x Number: %w", accountID, err)
		}
	}
	if len(account.UsernameHash) > 0 {
		usernameHash, err := base64.RawURLEncoding.DecodeString(account.UsernameHash)
		if err != nil {
			util.Log().Errorf("error decoding username hash. ACI: %s, username hash: %s, err: %v",
				base64.StdEncoding.EncodeToString(accountID), account.UsernameHash, err)
			return fmt.Errorf("updating %x username hash: failed to base64 decode hash: %w", accountID, err)
		}
		if err := updater.update(ctx, withinBackfill,
			append([]byte{shared.UsernameHashPrefix}, usernameHash...),
			marshalValue(accountID), updateHandler, nil); err != nil {
			util.Log().Errorf("error updating username hash. ACI: %s, username hash: %s, err: %v",
				base64.StdEncoding.EncodeToString(accountID), account.UsernameHash, err)
			return fmt.Errorf("updating %x username hash: %w", accountID, err)
		}
	}
	return nil
}

type mappingPair struct {
	PrevKey []byte
	PrevVal []byte
	NextKey []byte
	NextVal []byte
	Type    string
}

func update(ctx context.Context, updateHandler *KtUpdateHandler, updater Updater, pair *mappingPair) error {
	if pair.PrevKey == nil && pair.NextKey == nil {
		// This should never happen, but we want to know about it if it does
		metrics.IncrCounterWithLabels([]string{"stream_empty_pair"}, 1, []metrics.Label{{Name: "search_key_type", Value: pair.Type}})
		return nil
	} else if pair.NextKey == nil {
		if err := updater.update(ctx, withinStream,
			pair.PrevKey, tombstoneBytes, updateHandler, marshalValue(pair.PrevVal)); err != nil {
			return fmt.Errorf("updating %s: %w", pair.Type, err)
		}
	} else {
		if !bytes.Equal(pair.PrevVal, pair.NextVal) {
			if err := updater.update(ctx, withinStream,
				pair.NextKey, marshalValue(pair.NextVal), updateHandler, nil); err != nil {
				return fmt.Errorf("updating %s: %w", pair.Type, err)
			}
		} else {
			// This should also never happen, but we want to know about it if it does
			metrics.IncrCounterWithLabels([]string{"stream_duplicate_pair"}, 1, []metrics.Label{{Name: "search_key_type", Value: pair.Type}})
		}
	}
	return nil
}

type SearchKey interface {
	e164 | usernameHash | aci
}

type streamPair[T SearchKey] struct {
	Prev *T `json:"prev"`
	Next *T `json:"next"`
}

func updateFromStream[T SearchKey](
	ctx context.Context,
	data []byte,
	updateHandler *KtUpdateHandler,
	updater Updater,
	streamType string,
	extractKeyVal func(*T) (key []byte, value []byte),
) error {
	pair := &streamPair[T]{}
	if err := json.Unmarshal(data, pair); err != nil {
		// Note: This is not a temporary error and will intentionally cause the
		// scanner to get stuck until new code is deployed that can handle
		// whatever is in the stream.
		return fmt.Errorf("unmarshaling from %s stream: %w", streamType, err)
	}

	var prevKey, prevVal, nextKey, nextVal []byte
	if pair.Prev != nil {
		prevKey, prevVal = extractKeyVal(pair.Prev)
	}
	if pair.Next != nil {
		nextKey, nextVal = extractKeyVal(pair.Next)
	}

	return update(ctx, updateHandler, updater, &mappingPair{
		PrevKey: prevKey,
		PrevVal: prevVal,
		NextKey: nextKey,
		NextVal: nextVal,
		Type:    streamType,
	})
}

type e164 struct {
	Number string `json:"e164"`
	ACI    []byte `json:"aci"`
}

type updateFunc func(context.Context, []byte, *KtUpdateHandler, Updater) error

func updateFromE164Stream(ctx context.Context, data []byte, updateHandler *KtUpdateHandler, updater Updater) error {
	return updateFromStream(ctx, data, updateHandler, updater, "number",
		func(e *e164) (key []byte, value []byte) {
			return append([]byte{shared.NumberPrefix}, []byte(e.Number)...), e.ACI
		},
	)
}

type usernameHash struct {
	UsernameHash []byte `json:"usernameHash"`
	ACI          []byte `json:"aci"`
}

func updateFromUsernameStream(ctx context.Context, data []byte, updateHandler *KtUpdateHandler, updater Updater) error {
	return updateFromStream(ctx, data, updateHandler, updater, "usernameHash",
		func(u *usernameHash) (key []byte, value []byte) {
			return append([]byte{shared.UsernameHashPrefix}, u.UsernameHash...), u.ACI
		},
	)
}

type aci struct {
	ACI            []byte `json:"aci"`
	ACIIdentityKey []byte `json:"aciIdentityKey"`
}

func updateFromAciStream(ctx context.Context, data []byte, updateHandler *KtUpdateHandler, updater Updater) error {
	return updateFromStream(ctx, data, updateHandler, updater, "aci",
		func(a *aci) (key []byte, value []byte) {
			return append([]byte{shared.AciPrefix}, a.ACI...), a.ACIIdentityKey
		},
	)
}

// Updater interface supports mocking in tests
type Updater interface {
	update(ctx context.Context, within string, key, value []byte, handler *KtUpdateHandler, expectedPreUpdateValue []byte) error
}

type LogUpdater struct{}

func (s *LogUpdater) update(ctx context.Context, within string, key, value []byte, updateHandler *KtUpdateHandler, expectedPreUpdateValue []byte) (returnedErr error) {
	defer func() {
		success := returnedErr == nil
		metrics.IncrCounterWithLabels([]string{within, "items_processed"}, 1, []metrics.Label{{Name: "success", Value: strconv.FormatBool(success)}})
	}()
	updateReq := &pb.UpdateRequest{
		SearchKey:   key,
		Value:       value,
		Consistency: &pb.Consistency{}}

	if expectedPreUpdateValue != nil {
		updateReq.ExpectedPreUpdateValue = expectedPreUpdateValue
	}

	_, err := updateHandler.update(ctx, updateReq, 30*time.Minute)
	return err
}

func marshalValue(bytes []byte) []byte {
	// It's not clear to me if we'll want to store more information in the log
	// later. For now, prefix with a 0 as a format version identifier.
	return append([]byte{0}, bytes...)
}

func dup(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
