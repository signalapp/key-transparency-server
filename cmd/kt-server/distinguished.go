//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-metrics"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/internal/util"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

const (
	distinguishedSearchKey = "distinguished"
)

// distinguishedLookup looks up the value of the distinguished key, parses it as
// a Unix timestamp, and returns the timestamp.
func distinguishedLookup(updateHandler *KtUpdateHandler) time.Time {
	tree, err := updateHandler.config.NewTree(updateHandler.tx)
	if err != nil {
		util.Log().Fatalf("failed to initialize tree for distinguished lookup: %v", err)
	}
	for {
		res, err := tree.Search(&tpb.TreeSearchRequest{
			SearchKey:   []byte(distinguishedSearchKey),
			Consistency: &tpb.Consistency{},
		})
		metrics.IncrCounterWithLabels([]string{"distinguished_lookup"}, 1, []metrics.Label{successLabel(err)})
		if err != nil {
			errStr := err.Error()
			if gprcError, ok := status.FromError(err); ok && gprcError.Code() == codes.NotFound {
				return time.Time{}
			} else if strings.HasSuffix(errStr, "tree is empty") {
				return time.Time{}
			}
			util.Log().Warnf("Failed to lookup distinguished key: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		timestamp, err := strconv.ParseInt(string(res.Value.Value), 10, 64)
		if err != nil {
			util.Log().Fatalf("Failed to parse distinguished key value: %v", err)
		}
		return time.Unix(timestamp, 0)
	}
}

// distinguishedUpdate updates the value of the distinguished key to be the
// current time.
func distinguishedUpdate(updateHandler *KtUpdateHandler) {
	for i := 0; i < 5; i++ {
		_, err := updateHandler.update(context.Background(), &tpb.UpdateRequest{
			SearchKey:   []byte(distinguishedSearchKey),
			Value:       []byte(fmt.Sprint(time.Now().Unix())),
			Consistency: &tpb.Consistency{},
		}, 5*time.Second)
		metrics.IncrCounterWithLabels([]string{"distinguished_update"}, 1, []metrics.Label{successLabel(err)})
		if err == nil {
			treeHead, _, err := updateHandler.tx.GetHead()
			if err != nil {
				util.Log().Warnf("failed to fetch head: %v", err)
				return
			}
			metrics.SetGauge([]string{"distinguished.tree_size"}, float32(treeHead.TreeSize))
			return
		}
		util.Log().Warnf("Failed to update distinguished key: %v", err)
		time.Sleep(5 * time.Second)
	}
	util.Log().Warnf("Failed to update distinguished key")
}

// distinguished maintains a distinguished key in the log.
func distinguished(updateHandler *KtUpdateHandler, interval time.Duration) {
	var durUntilNext time.Duration

	durSinceLast := time.Now().Sub(distinguishedLookup(updateHandler))
	if durSinceLast < interval {
		durUntilNext = interval - durSinceLast
	}

	for {
		time.Sleep(durUntilNext)
		distinguishedUpdate(updateHandler)
		durUntilNext = interval
	}
}
