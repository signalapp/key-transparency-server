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
	"sync"
	"sync/atomic"
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

// shardMap implements locking around a map from shard id to shard state, used
// to coordinate many updater goroutines processing Kinesis records.
type shardMap struct {
	mutex sync.Mutex

	// done is set to true when the Kinesis stream is being shutdown. This
	// prevents any further updates from being processed.
	done bool
	// shards is a map from shard id to shard state.
	shards map[string]*shardState
}

func newShardMap() *shardMap {
	return &shardMap{
		mutex: sync.Mutex{},

		done:   false,
		shards: make(map[string]*shardState),
	}
}

// start starts a new update for the given shard id. It returns the shard state.
// If the stream is being shutdown, it returns nil.
func (sm *shardMap) start(id string) *shardState {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.done {
		return nil
	}

	if _, ok := sm.shards[id]; !ok {
		sm.shards[id] = &shardState{}
	}
	state := sm.shards[id]
	state.start()

	return state
}

// finish stops new updates from being processed and waits for all existing
// updates to finish.
func (sm *shardMap) finish() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.done = true
	for _, shard := range sm.shards {
		shard.waitGroup.Wait()
	}
}

// shardState is the update state for an individual Kinesis shard.
type shardState struct {
	// sinceLast is the number of records processed since the last checkpoint.
	sinceLast int
	// waitGroup tracks when all pending updates have been processed.
	waitGroup sync.WaitGroup
	// searchKeyLocks is a map from a search key to chan struct{}. It prevents multiple updates
	// from being processed for the same search key simultaneously.
	searchKeyLocks sync.Map
	// didFail is set to true if any updates failed to process.
	didFail atomic.Bool
}

func (ss *shardState) start() {
	ss.sinceLast++
	ss.waitGroup.Add(1)
}

// wait waits for all pending updates to finish. It returns true if any of the
// updates failed to process.
func (ss *shardState) wait() bool {
	ss.waitGroup.Wait()
	ss.sinceLast = 0
	return ss.didFail.Load()
}

// lockSearchKey blocks until it is able to get an exclusive lock on the given search key. No
// other goroutines are able to obtain a lock until `unlock` is called.
func (ss *shardState) lockSearchKey(searchKey []byte) (unlock func()) {
	searchKeyString := fmt.Sprintf("%x", searchKey)
	ch := make(chan struct{})
	for {
		existing, locked := ss.searchKeyLocks.LoadOrStore(searchKeyString, ch)
		if locked {
			// This search key is already locked. Wait for it to be unlocked and retry.
			<-existing.(chan struct{})
			continue
		}
		return func() {
			ss.searchKeyLocks.CompareAndDelete(searchKeyString, ch)
			close(ch)
		}
	}
}

func (ss *shardState) failed() { ss.didFail.Store(true) }
func (ss *shardState) done()   { ss.waitGroup.Done() }

type Streamer struct {
	config *config.APIConfig
	tx     db.TransparencyStore
}

// run runs the streamer, blocking forever.
func (s *Streamer) run(ctx context.Context, name string, startAtTimestamp *time.Time, updateHandler *KtUpdateHandler,
	updateFunc updateFunc, checkpointSize uint) {
	i := 0
	for {
		// Create a new context and shard map for each run.
		runCtx, cancel := context.WithCancel(ctx)
		shards := newShardMap()

		// Note on thread safety: The Kinesis consumer library will use one
		// goroutine per shard to scan. As such, a mutex is required to lookup shard
		// state from the `shards` map because many shards may be read/written to
		// the map in parallel. But the returned shardState struct can then be used
		// without a mutex because there is only one goroutine working with it.

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
			util.Log().Errorf("stream consumer initialization error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		startAtTimestamp = nil

		err = c.Scan(runCtx, func(r *consumer.Record) error {
			// If start returns nil, the stream is shutting down and we should exit
			state := shards.start(r.ShardID)
			if state == nil {
				return consumer.ErrSkipCheckpoint
			}

			go func(ctx context.Context, data []byte, state *shardState) {
				defer state.done()

				for {
					select {
					case <-ctx.Done():
						state.failed()
						return
					default:
						err := updateFunc(ctx, data, state, updateHandler, logUpdater)
						if err != nil {
							util.Log().Infof("failed to update entry from stream: %v", err)
							metrics.IncrCounter([]string{withinStream, "errors"}, 1)
							time.Sleep(3 * time.Second)
						} else {
							return
						}
					}
				}
			}(runCtx, dup(r.Data), state)

			// If only a few entries have been sequenced from this shard, move on.
			if uint(state.sinceLast) < checkpointSize {
				return consumer.ErrSkipCheckpoint
			}
			// If many entries have been sequenced, we need to checkpoint. First
			// wait for all processing updates to complete.
			if failed := state.wait(); failed {
				return consumer.ErrSkipCheckpoint
			}
			return nil
		})
		util.Log().Errorf("stream consumer error: %v", err)

		// We only reach this point if c.Scan returns an error.
		// In this case, clean up the current context, sleep with an exponential backoff,
		// and wait for all spawned goroutines to exit.
		cancel()

		// Cap the backoff at 60 seconds
		delay := time.Duration(math.Min(60, math.Pow(2, float64(i)))) * time.Second
		util.Log().Infof("iteration %d of stream consumer, sleeping %s", i, delay)
		time.Sleep(delay)

		// Ensure that all update goroutines have exited before restarting the consumer
		shards.finish()
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
				metrics.IncrCounter([]string{withinBackfill, "shards_processed"}, 1)
				util.Log().Infof("Finished processing of backfill shard %d: err=%v", shard, returnedErr)
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
			return fmt.Errorf("processing item %d: %w", i, err)
		}
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
		return fmt.Errorf("account ID not bytes")
	} else if len(ub.Value) != 16 {
		return fmt.Errorf("account ID not valid")
	}
	accountID := ub.Value
	d := item["D"]
	if d == nil {
		return fmt.Errorf("account %x no data", accountID)
	}
	db, ok := d.(*types.AttributeValueMemberB)
	if !ok {
		return fmt.Errorf("account %x data not bytes", accountID)
	}
	var account backfillAccount
	if err := json.Unmarshal(db.Value, &account); err != nil {
		return fmt.Errorf("parsing account %x data: %w", accountID, err)
	} else if len(account.Number) == 0 {
		return fmt.Errorf("account %x data has empty number", accountID)
	}
	if len(account.ACIIdentityKey) > 0 {
		if err := updater.update(ctx, withinBackfill,
			append([]byte{shared.AciPrefix}, accountID...),
			marshalValue(account.ACIIdentityKey), updateHandler, nil); err != nil {
			return fmt.Errorf("updating %x ACI: %w", accountID, err)
		}
	}
	if len(account.Number) > 0 {
		if err := updater.update(ctx, withinBackfill,
			append([]byte{shared.NumberPrefix}, []byte(account.Number)...),
			marshalValue(accountID), updateHandler, nil); err != nil {
			return fmt.Errorf("updating %x Number: %w", accountID, err)
		}
	}
	if len(account.UsernameHash) > 0 {
		usernameHash, err := base64.RawURLEncoding.DecodeString(account.UsernameHash)
		if err != nil {
			return fmt.Errorf("updating %x username hash: failed to base64 decode hash: %w", accountID, err)
		}
		if err := updater.update(ctx, withinBackfill,
			append([]byte{shared.UsernameHashPrefix}, usernameHash...),
			marshalValue(accountID), updateHandler, nil); err != nil {
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

func update(ctx context.Context, state *shardState, updateHandler *KtUpdateHandler, updater Updater, pair *mappingPair) error {
	if pair.PrevKey == nil && pair.NextKey == nil {
		// This should never happen, but we want to know about it if it does
		metrics.IncrCounterWithLabels([]string{"stream_empty_pair"}, 1, []metrics.Label{{Name: "search_key_type", Value: pair.Type}})
		return nil
	} else if pair.NextKey == nil {
		defer state.lockSearchKey(pair.PrevKey)()
		if err := updater.update(ctx, withinStream,
			pair.PrevKey, tombstoneBytes, updateHandler, marshalValue(pair.PrevVal)); err != nil {
			return fmt.Errorf("updating %s: %w", pair.Type, err)
		}
	} else {
		defer state.lockSearchKey(pair.NextKey)()
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
	state *shardState,
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

	return update(ctx, state, updateHandler, updater, &mappingPair{
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

type updateFunc func(context.Context, []byte, *shardState, *KtUpdateHandler, Updater) error

func updateFromE164Stream(ctx context.Context, data []byte, state *shardState, updateHandler *KtUpdateHandler, updater Updater) error {
	return updateFromStream(ctx, data, state, updateHandler, updater, "number",
		func(e *e164) (key []byte, value []byte) {
			return append([]byte{shared.NumberPrefix}, []byte(e.Number)...), e.ACI
		},
	)
}

type usernameHash struct {
	UsernameHash []byte `json:"usernameHash"`
	ACI          []byte `json:"aci"`
}

func updateFromUsernameStream(ctx context.Context, data []byte, state *shardState, updateHandler *KtUpdateHandler, updater Updater) error {
	return updateFromStream(ctx, data, state, updateHandler, updater, "usernameHash",
		func(u *usernameHash) (key []byte, value []byte) {
			return append([]byte{shared.UsernameHashPrefix}, u.UsernameHash...), u.ACI
		},
	)
}

type aci struct {
	ACI            []byte `json:"aci"`
	ACIIdentityKey []byte `json:"aciIdentityKey"`
}

func updateFromAciStream(ctx context.Context, data []byte, state *shardState, updateHandler *KtUpdateHandler, updater Updater) error {
	return updateFromStream(ctx, data, state, updateHandler, updater, "aci",
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
