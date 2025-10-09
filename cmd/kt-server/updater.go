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
			if isTombstoneUpdate(first.req.GetUpdateRequest()) {
				handleTombstoneUpdate(tree, first)
				sinceLastTick++
				continue // Do not start a batch of updates
			}

			reqs := []updateRequest{first}
			var tombstoneUpdate *updateRequest
		loop:
			for {
				select {
				case req := <-ch:
					// If the channel receives a tombstone update, process the batch of updates so far
					// and then handle the tombstone update separately to preserve the ordering of the updates
					// as they're received from the channel.
					if isTombstoneUpdate(req.req.GetUpdateRequest()) {
						tombstoneUpdate = &req
						break loop
					} else {
						reqs = append(reqs, req)
					}
				default:
					break loop
				}
			}

			start := time.Now()

			states := make([]*transparency.PreUpdateState, len(reqs))
			for i, req := range reqs {
				states[i] = req.req
			}
			res, err := tree.BatchUpdate(states)

			incrementInsertMetrics(err, start, float32(len(states)), true)
			sinceLastTick += len(reqs)

			for i, req := range reqs {
				// These channel writes are guaranteed to not block, since this is the
				// only time we write to them, and they're buffered channels of size 1.
				if err == nil {
					req.res <- updateResponse{res: res[i], err: nil}
				} else {
					req.res <- updateResponse{res: nil, err: err}
				}
			}

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
