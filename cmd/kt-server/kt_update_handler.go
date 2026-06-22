//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	metrics "github.com/hashicorp/go-metrics"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/db"
	t "github.com/signalapp/keytransparency/tree"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

type KtUpdateHandler struct {
	config *config.APIConfig
	tx     db.TransparencyStore
	ch     chan<- updateRequest

	pb.UnimplementedKeyTransparencyTestServiceServer
}

func (h *KtUpdateHandler) Update(ctx context.Context, req *tpb.UpdateRequest) (*tpb.UpdateResponse, error) {
	start := time.Now()
	res, err := h.update(ctx, req, 5*time.Second)
	grpcErr := toGrpcError(err)
	labels := []metrics.Label{successLabel(grpcErr), grpcStatusLabel(grpcErr)}
	metrics.IncrCounterWithLabels([]string{"update_requests"}, 1, labels)
	metrics.MeasureSinceWithLabels([]string{"update_duration"}, start, labels)
	if err, _ := status.FromError(grpcErr); err.Code() == codes.Unknown {
		util.Log().Errorf("Unexpected update error in key transparency service: %v", err.Err())
	}
	return res, grpcErr
}

func (h *KtUpdateHandler) update(ctx context.Context, req *tpb.UpdateRequest, timeout time.Duration) (*tpb.UpdateResponse, error) {
	tree, err := h.config.NewTree(h.tx)
	if err != nil {
		return nil, err
	}
	pre, err := tree.PreUpdate(req)
	if err != nil {
		return nil, err
	}

	ch := make(chan updateResponse, 1)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case h.ch <- updateRequest{req: pre, res: ch}:
	case <-ctx.Done():
		return nil, fmt.Errorf("submitting insertion request timed out: %w", ctx.Err())
	}
	select {
	case res := <-ch:
		if res.err != nil {
			if errors.Is(res.err, t.ErrDuplicateUpdate) {
				searchKeyTypeLabel, err := GetSearchKeyTypeLabel(req.SearchKey)
				if err != nil {
					return nil, err
				}
				metrics.IncrCounterWithLabels([]string{"internal_update_error"}, 1, []metrics.Label{searchKeyTypeLabel, {Name: "reason", Value: "duplicate_update"}})
				return nil, nil
			}

			return nil, res.err
		}
		if req.ReturnUpdateResponse {
			return tree.PostUpdate(res.res)
		}
		return nil, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for insertion result timed out: %w", ctx.Err())
	}
}
