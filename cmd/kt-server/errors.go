package main

import (
	"cmp"
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	commonerrors "github.com/signalapp/keytransparency/common-errors"
	"github.com/signalapp/keytransparency/tree"
)

const (
	constraintViolatedReason = "CONSTRAINT_VIOLATED"
	unavailableReason        = "UNAVAILABLE"
	ktDomain                 = "kt.signal.org"
)

var (
	errInternal               = errors.New("internal error")
	errInfoConstraintViolated = &errdetails.ErrorInfo{
		Domain: ktDomain,
		Reason: constraintViolatedReason,
	}
)

// toErrType is used by the V2 RPCs on KeyTransparencyQueryService
func toErrType(err error) ErrType {
	var invalidArg *commonerrors.ErrInvalidArgument
	var invalidTreeConfiguration *tree.ErrInvalidTreeConfiguration
	var permissionDenied *commonerrors.ErrPermissionDenied

	switch {
	case err == nil:
		return nil
	case errors.As(err, &invalidArg):
		return &GrpcErr{err: fieldViolation(invalidArg.Field, invalidArg.Message)}
	case errors.As(err, &invalidTreeConfiguration):
		return &GrpcErr{err: unavailable(invalidTreeConfiguration.Error())}
	case errors.As(err, &permissionDenied):
		return &PermissionDeniedErr{&pb.PermissionDenied{}}
	default:
		return &GrpcErr{err: unavailable("unexpected error"), internal: err}
	}
}

type ErrType interface {
	errType()
}

type GrpcErr struct {
	err      error
	internal error // used for logging more detail on unexpected internal errors. nil on typed domain errors.
}

func (e *GrpcErr) errType() {}

type PermissionDeniedErr struct {
	*pb.PermissionDenied
}

func (e *PermissionDeniedErr) errType() {}

func fieldViolation(fieldName, message string) error {
	st := status.New(codes.InvalidArgument, messageOrDefault(message, codes.InvalidArgument))
	details := &errdetails.BadRequest_FieldViolation{
		Field:       fieldName,
		Description: message,
	}
	br := &errdetails.BadRequest{}
	br.FieldViolations = append(br.FieldViolations, details)
	st, err := st.WithDetails(errInfoConstraintViolated, br)

	if err != nil {
		panic(fmt.Sprintf("Unexpected error attaching field violation metadata: %v", err))
	}

	return st.Err()
}

func unavailable(message string) error {
	st := status.New(codes.Unavailable, messageOrDefault(message, codes.Unavailable))
	details := &errdetails.ErrorInfo{
		Domain: ktDomain,
		Reason: unavailableReason,
	}
	st, err := st.WithDetails(details)

	if err != nil {
		panic(fmt.Sprintf("Unexpected error attaching details: %v", err))
	}

	return st.Err()
}

func messageOrDefault(message string, code codes.Code) string {
	return cmp.Or(message, code.String())
}
