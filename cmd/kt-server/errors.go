package main

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonerrors "github.com/signalapp/keytransparency/common-errors"
	"github.com/signalapp/keytransparency/tree"
)

var (
	errInternal = errors.New("internal error")
)

func toGrpcError(err error) error {
	var invalidArg *commonerrors.ErrInvalidArgument
	var invalidTreeConfiguration *tree.ErrInvalidTreeConfiguration
	var permissionDenied *commonerrors.ErrPermissionDenied
	var auditorSignatureVerificationFailed *tree.ErrAuditorSignatureVerificationFailed

	switch {
	case err == nil:
		return nil
	case errors.As(err, &invalidArg):
		return status.Error(codes.InvalidArgument, invalidArg.Error())
	case errors.As(err, &invalidTreeConfiguration):
		return status.Error(codes.FailedPrecondition, invalidTreeConfiguration.Error())
	case errors.As(err, &permissionDenied):
		return status.Error(codes.PermissionDenied, permissionDenied.Error())
	case errors.Is(err, tree.ErrEmptyTree):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &auditorSignatureVerificationFailed):
		return status.Error(codes.FailedPrecondition, auditorSignatureVerificationFailed.Error())
	case errors.Is(err, tree.ErrOutOfRange):
		return status.Error(codes.OutOfRange, err.Error())
	case errors.Is(err, errInternal):
		return status.Error(codes.Internal, err.Error())
	default:
		return status.Error(codes.Unknown, err.Error())
	}
}
