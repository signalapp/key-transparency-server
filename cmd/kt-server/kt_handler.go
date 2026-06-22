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
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree"
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
	tree, err := h.config.NewTree(h.tx)
	return &pb.TreeSizeResponse{TreeSize: tree.GetTransparencyTreeHead().TreeSize}, err
}

func (h *KtHandler) Audit(ctx context.Context, req *pb.AuditRequest) (*pb.AuditResponse, error) {
	return h.audit(ctx, req)
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
		return nil, toGrpcError(err)
	}
	return &pb.AuditResponse{Updates: updates, More: more}, nil
}

func (h *KtHandler) SetAuditorHead(ctx context.Context, head *tpb.AuditorTreeHead) (*emptypb.Empty, error) {
	auditor, err := extractAuditorName(ctx)
	if err != nil {
		return nil, err
	}
	return h.setAuditorHead(ctx, head, auditor)
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
		if err != nil {
			if _, ok := errors.AsType[*tree.ErrAuditorSignatureVerificationFailed](err); ok {
				util.Log().Errorf("failed to verify auditor tree head signature: %s", err.Error())
			}
			grpcErr := toGrpcError(err)
			// Return Unavailable instead of Unknown for unexpected errors for backwards compatability
			if s, _ := status.FromError(grpcErr); s.Code() == codes.Unknown {
				util.Log().Errorf("unexpected error setting auditor tree head: %v", grpcErr)
				return nil, status.Error(codes.Unavailable, grpcErr.Error())
			}
			return nil, grpcErr
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
