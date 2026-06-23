package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	commonerrors "github.com/signalapp/keytransparency/common-errors"
	"github.com/signalapp/keytransparency/tree"
)

func TestToErrType_Nil(t *testing.T) {
	if toErrType(nil) != nil {
		t.Fatalf("expected nil for nil error")
	}
}

func TestToErrType_InvalidArgument(t *testing.T) {
	expectedField := "test_field"
	expectedMessage := "test_message"
	invalidArgErr := &commonerrors.ErrInvalidArgument{Field: expectedField, Message: expectedMessage}
	errType := toErrType(invalidArgErr)

	grpcErr, ok := errType.(*GrpcErr)
	if !ok {
		t.Fatalf("expected error to be of type GrpcErr")
	}

	st, ok := status.FromError(grpcErr.err)
	if !ok {
		t.Fatalf("expected error to be of type status.Status")
	}

	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected status.Code to be InvalidArgument")
	}

	var errInfo *errdetails.ErrorInfo
	var badRequest *errdetails.BadRequest
	for _, detail := range st.Details() {
		if br, ok := detail.(*errdetails.BadRequest); ok {
			badRequest = br
		}
		if ei, ok := detail.(*errdetails.ErrorInfo); ok {
			errInfo = ei
		}
	}

	assert.Equal(t, expectedField, badRequest.FieldViolations[0].GetField())
	assert.Equal(t, expectedMessage, badRequest.FieldViolations[0].GetDescription())
	assert.Equal(t, ktDomain, errInfo.GetDomain())
	assert.Equal(t, constraintViolatedReason, errInfo.GetReason())
}

func TestToErrType_InvalidTreeConfiguration(t *testing.T) {
	expectedField := "test_field"
	expectedMessage := "test_message"
	invalidTreeConfigurationErr := &tree.ErrInvalidTreeConfiguration{Field: expectedField, Message: expectedMessage}

	errType := toErrType(invalidTreeConfigurationErr)

	grpcErr, ok := errType.(*GrpcErr)
	if !ok {
		t.Fatalf("expected error to be of type GrpcErr")
	}

	st, ok := status.FromError(grpcErr.err)
	if !ok {
		t.Fatalf("expected error to be of type status.Status")
	}

	if st.Code() != codes.Unavailable {
		t.Fatalf("expected status.Code to be Unavailable")
	}

	if st.Message() != invalidTreeConfigurationErr.Error() {
		t.Fatalf("expected status.Message to be %s, got %s", invalidTreeConfigurationErr.Error(), st.Message())
	}

	var errInfo *errdetails.ErrorInfo
	for _, detail := range st.Details() {
		if ei, ok := detail.(*errdetails.ErrorInfo); ok {
			errInfo = ei
		}
	}

	assert.Equal(t, ktDomain, errInfo.GetDomain())
	assert.Equal(t, unavailableReason, errInfo.GetReason())
}

func TestToErrType_PermissionDenied(t *testing.T) {
	permissionDeniedErr := &commonerrors.ErrPermissionDenied{Message: "test message"}

	errType := toErrType(permissionDeniedErr)

	pdErr, ok := errType.(*PermissionDeniedErr)
	if !ok {
		t.Fatalf("expected error to be of type PermissionDeniedErr")
	}

	assert.Equal(t, &pb.PermissionDenied{}, pdErr.PermissionDenied)
}

func TestToErrType_Default(t *testing.T) {
	msg := "unexpected error"
	unexpectedErr := errors.New(msg)

	errType := toErrType(unexpectedErr)

	grpcErr, ok := errType.(*GrpcErr)
	if !ok {
		t.Fatalf("expected error to be of type GrpcErr")
	}

	st, ok := status.FromError(grpcErr.err)
	if !ok {
		t.Fatalf("expected error to be of type status.Status")
	}

	if st.Code() != codes.Unavailable {
		t.Fatalf("expected status.Code to be Unavailable")
	}

	if st.Message() != unexpectedErr.Error() {
		t.Fatalf("expected status.Message to be %s, got %s", unexpectedErr.Error(), st.Message())
	}

	var errInfo *errdetails.ErrorInfo
	for _, detail := range st.Details() {
		if ei, ok := detail.(*errdetails.ErrorInfo); ok {
			errInfo = ei
		}
	}

	assert.Equal(t, ktDomain, errInfo.GetDomain())
	assert.Equal(t, unavailableReason, errInfo.GetReason())
}
