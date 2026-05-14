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
					metrics.IncrCounterWithLabels([]string{"inserts"}, float32(numFakeUpdatesNeeded), []metrics.Label{realLabel(false), successLabel(err)})
					incrementInsertOperationMetrics(err, start, float32(numFakeUpdatesNeeded), false)
					if err != nil {
						util.Log().Warnf("Error applying fake updates: %v", err)
						continue
					}
				}
			}
			sinceLastTick = 0

		case first := <-ch: // Handle a real request to update the tree.
			reqs := collectBatch(ch, first)

			states := make([]*transparency.PreUpdateState, len(reqs))
			tombstoneCount := 0

			for i, req := range reqs {
				if isTombstoneUpdate(req.req.Req) {
					tombstoneCount++
				}
				states[i] = req.req
			}

			start := time.Now()
			res, err := tree.BatchUpdate(states)

			streamCount := len(reqs) - tombstoneCount
			metrics.IncrCounterWithLabels([]string{"inserts"}, float32(streamCount), []metrics.Label{realLabel(true), successLabel(err), tombstoneLabel(false)})
			metrics.IncrCounterWithLabels([]string{"inserts"}, float32(tombstoneCount), []metrics.Label{realLabel(true), successLabel(err), tombstoneLabel(true)})
			incrementInsertOperationMetrics(err, start, float32(len(states)), true)

			sinceLastTick += len(reqs)

			for i, req := range reqs {
				// These channel writes are guaranteed to not block, since this is the
				// only time we write to them, and they're buffered channels of size 1.
				if err == nil {
					if res[i].Err() != nil {
						req.res <- updateResponse{res: nil, err: res[i].Err()}
					} else {
						req.res <- updateResponse{res: res[i], err: nil}
					}
				} else {
					req.res <- updateResponse{res: nil, err: err}
				}
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

// drainChannel drains update requests from the provided channel.
func collectBatch(ch chan updateRequest, first updateRequest) []updateRequest {
	reqs := []updateRequest{first}

	for {
		select {
		case req := <-ch:
			reqs = append(reqs, req)
		default:
			return reqs
		}
	}
}

func incrementInsertOperationMetrics(err error, start time.Time, batchSize float32, real bool) {
	metrics.IncrCounterWithLabels([]string{"insert_operations"}, 1, []metrics.Label{realLabel(real), successLabel(err), grpcStatusLabel(err)})
	metrics.AddSampleWithLabels([]string{"insert_batch_size"}, batchSize, []metrics.Label{realLabel(real), successLabel(err)})
	metrics.MeasureSinceWithLabels([]string{"insert_duration"}, start, []metrics.Label{realLabel(real), successLabel(err)})
}
