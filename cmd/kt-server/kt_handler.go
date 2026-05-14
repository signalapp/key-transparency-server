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

	"github.com/hashicorp/go-metrics"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/tree/transparency"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/db"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

type KtHandler struct {
	config             *config.APIConfig
	tx                 db.TransparencyStore
	ch                 chan<- updateRequest
	auditorTreeHeadsCh chan<- updateAuditorTreeHeadRequest // Channel used to set auditor tree heads

	pb.UnimplementedKeyTransparencyAuditorServiceServer
}

func (h *KtHandler) TreeSize(ctx context.Context, req *emptypb.Empty) (*pb.TreeSizeResponse, error) {
	auditor, err := extractAuditorName(ctx)
	if err != nil {
		return nil, err
	}
	tree, err := h.config.NewTree(h.tx)
	labels := []metrics.Label{successLabel(err), auditorLabel(auditor)}
	metrics.IncrCounterWithLabels([]string{"tree_size_requests"}, 1, labels)
	return &pb.TreeSizeResponse{TreeSize: tree.GetTransparencyTreeHead().TreeSize}, err
}

func (h *KtHandler) Audit(ctx context.Context, req *pb.AuditRequest) (*pb.AuditResponse, error) {
	auditor, err := extractAuditorName(ctx)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	res, err := h.audit(ctx, req)
	labels := []metrics.Label{successLabel(err), auditorLabel(auditor)}
	metrics.IncrCounterWithLabels([]string{"audit_requests"}, 1, labels)
	metrics.MeasureSinceWithLabels([]string{"audit_duration"}, start, labels)
	return res, err
}

func (h *KtHandler) audit(ctx context.Context, req *pb.AuditRequest) (*pb.AuditResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	tree, err := h.config.NewTree(h.tx)
	if err != nil {
		return nil, err
	}
	updates, more, err := tree.Audit(req.Start, req.Limit)
	if err != nil {
		if errors.Is(err, transparency.ErrInvalidArgument) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		} else if errors.Is(err, transparency.ErrOutOfRange) {
			return nil, status.Error(codes.OutOfRange, err.Error())
		}
		return nil, err
	}
	return &pb.AuditResponse{Updates: updates, More: more}, nil
}

func (h *KtHandler) SetAuditorHead(ctx context.Context, head *tpb.AuditorTreeHead) (*emptypb.Empty, error) {
	start := time.Now()
	auditor, err := extractAuditorName(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.setAuditorHead(ctx, head, auditor)
	labels := []metrics.Label{successLabel(err), auditorLabel(auditor)}
	metrics.IncrCounterWithLabels([]string{"auditor_head_requests"}, 1, labels)
	metrics.MeasureSinceWithLabels([]string{"auditor_head_duration"}, start, labels)
	return res, err
}

func (h *KtHandler) setAuditorHead(ctx context.Context, head *tpb.AuditorTreeHead, auditorName string) (*emptypb.Empty, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	errorCh := make(chan error, 1)
	select {
	case h.auditorTreeHeadsCh <- updateAuditorTreeHeadRequest{auditorTreeHead: head, auditorName: auditorName, err: errorCh}:
	case <-ctx.Done():
		return nil, fmt.Errorf("submitting auditor head timed out: %w", ctx.Err())
	}

	select {
	case err := <-errorCh:
		if errors.Is(err, transparency.ErrInvalidArgument) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		} else if _, isType := err.(*transparency.ErrAuditorSignatureVerificationFailed); isType {
			util.Log().Errorf("failed to verify auditor tree head signature: %s", err.Error())
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		} else if errors.Is(err, transparency.ErrFailedPrecondition) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		} else if err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for auditor head insertion result timed out: %w", ctx.Err())
	}
	return &emptypb.Empty{}, nil
}

// Checks that the auditor name exists on the incoming context and if so, parses and returns it
func extractAuditorName(ctx context.Context) (string, error) {
	auditorName, ok := ctx.Value(AuditorNameContextKey).(string)
	if !ok {
		return "", status.Error(codes.InvalidArgument, fmt.Sprintf("invalid type for auditor name. expected string, got %T", auditorName))
	}

	if len(auditorName) == 0 {
		return "", status.Error(codes.InvalidArgument, "no auditor name in context")
	}

	return auditorName, nil
}
