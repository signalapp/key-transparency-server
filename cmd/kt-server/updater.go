//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"time"

	metrics "github.com/hashicorp/go-metrics"
	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/tree/transparency"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

type updateRequest struct {
	req *transparency.PreUpdateState
	res chan<- updateResponse
}

type updateResponse struct {
	res *transparency.PostUpdateState
	err error
}

type updateAuditorTreeHeadRequest struct {
	auditorTreeHead *tpb.AuditorTreeHead
	auditorName     string
	err             chan<- error
}

// updater is a goroutine that:
// - Updates the log from the Kinesis account update stream by receiving update requests over `ch`
// - Updates the "distinguished" key by receiving update requests over `ch`
// - Inserts fake updates
// - Sets the auditor tree head
func updater(tree *transparency.Tree, ch chan updateRequest, auditorTreeHeadsCh chan updateAuditorTreeHeadRequest, fake *config.FakeUpdates) {
	var ticker <-chan time.Time
	if fake != nil {
		ticker = time.NewTicker(fake.Interval).C
	}

	sinceLastTick := 0
	for {
		select {
		case <-ticker: // Apply some fake updates to keep update rate consistent.
			if tree.CanFakeUpdate() {
				if sinceLastTick < fake.Count {
					numFakeUpdatesNeeded := fake.Count - sinceLastTick
					start := time.Now()
					err := tree.BatchUpdateFake(numFakeUpdatesNeeded)
					incrementInsertMetrics(err, start, float32(numFakeUpdatesNeeded), false)
					if err != nil {
						util.Log().Warnf("Error applying fake updates: %v", err)
						continue
					}
				}
			}
			sinceLastTick = 0

		case first := <-ch: // Handle a real request to update the tree.
			// Check if it's a tombstone update. If so, write the update immediately instead of starting a batch.
			if isTombstoneUpdate(first.req.Req) {
				handleTombstoneUpdate(tree, first)
				sinceLastTick++
				continue
			}

			// Collect any additional updates requests already in the channel, stopping at the first tombstone update.
			// It's important to write the tombstone update in order and separately to prevent incorrect state
			// resulting from a race between the tombstone update and another user claiming the old identifier.
			additionalNonTombstoneUpdates, tombstoneUpdate := collectUpdateBatch(ch)
			allNonTombstoneUpdates := append([]updateRequest{first}, additionalNonTombstoneUpdates...)

			start := time.Now()

			// Handle the non-tombstone updates
			states := make([]*transparency.PreUpdateState, len(allNonTombstoneUpdates))
			for i, req := range allNonTombstoneUpdates {
				states[i] = req.req
			}
			res, err := tree.BatchUpdate(states)

			incrementInsertMetrics(err, start, float32(len(states)), true)
			sinceLastTick += len(allNonTombstoneUpdates)

			for i, req := range allNonTombstoneUpdates {
				// These channel writes are guaranteed to not block, since this is the
				// only time we write to them, and they're buffered channels of size 1.
				if err == nil {
					req.res <- updateResponse{res: res[i], err: nil}
				} else {
					req.res <- updateResponse{res: nil, err: err}
				}
			}

			// Handle the tombstone update
			if tombstoneUpdate != nil {
				handleTombstoneUpdate(tree, *tombstoneUpdate)
				sinceLastTick++
			}

		case req := <-auditorTreeHeadsCh: // We received a new tree head from our auditor.
			if err := tree.SetAuditorHead(req.auditorTreeHead, req.auditorName); err != nil {
				util.Log().Warnf("Error updating auditor head: %v", err)
				req.err <- err
			} else {
				req.err <- nil
			}
		}
	}
}

// collectUpdateBatch drains update requests from the provided channel, discarding the update if it will not change the value
// of its most recent mapping and stopping at the first tombstone update it encounters.
// Returns the batch of update requests and any tombstone update encountered.
func collectUpdateBatch(ch chan updateRequest) ([]updateRequest, *updateRequest) {
	var reqs []updateRequest

	for {
		select {
		case req := <-ch:
			// If the channel receives a tombstone update, return the batch of updates so far
			// separate from the tombstone update.
			if isTombstoneUpdate(req.req.Req) {
				return reqs, &req
			}
			reqs = append(reqs, req)
		default:
			return reqs, nil
		}
	}
}

func incrementInsertMetrics(err error, start time.Time, batchSize float32, real bool) {
	metrics.IncrCounterWithLabels([]string{"inserts"}, batchSize, []metrics.Label{realLabel(real), successLabel(err)})
	metrics.IncrCounterWithLabels([]string{"insert_operations"}, 1, []metrics.Label{realLabel(real), successLabel(err), grpcStatusLabel(err)})
	metrics.AddSampleWithLabels([]string{"insert_batch_size"}, batchSize, []metrics.Label{realLabel(real), successLabel(err)})
	metrics.MeasureSinceWithLabels([]string{"insert_duration"}, start, []metrics.Label{realLabel(real), successLabel(err)})
}

func handleTombstoneUpdate(tree *transparency.Tree, internalUpdateRequest updateRequest) {
	start := time.Now()
	res, err := tree.UpdateExistingIndexWithTombstoneValue(internalUpdateRequest.req)
	metrics.IncrCounterWithLabels([]string{"tombstone_update"}, 1, []metrics.Label{successLabel(err), grpcStatusLabel(err)})
	incrementInsertMetrics(err, start, 1, true)

	if err == nil {
		internalUpdateRequest.res <- updateResponse{res: res, err: nil}
	} else {
		internalUpdateRequest.res <- updateResponse{res: nil, err: err}
	}
}
