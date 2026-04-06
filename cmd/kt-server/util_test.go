//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/shared"
)

var (
	validAci1            = random(16)
	mismatchedAci        = createDistinctValue(validAci1)
	validAciIdentityKey1 = random(16)
)

func random(length int) []byte {
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

var testVerifyMappedValueParameters = []struct {
	providedValue     []byte
	expectedValue     []byte
	expectedErrorType codes.Code
}{
	{validAci1, validAci1, codes.OK},
	{validAciIdentityKey1, validAciIdentityKey1, codes.OK},
	{validAci1, mismatchedAci, codes.PermissionDenied},
}

func TestVerifyMappedValueConstantTime(t *testing.T) {
	for _, p := range testVerifyMappedValueParameters {
		err := verifyMappedValueConstantTime(p.providedValue, p.expectedValue)
		if (p.expectedErrorType != codes.OK) != (err != nil) {
			t.Fatalf("Expected %v, got %v",
				p.expectedErrorType, err)
		}

		if p.expectedErrorType != codes.OK {
			if grpcError, ok := status.FromError(err); grpcError.Code() != p.expectedErrorType || !ok {
				t.Fatalf("Expected error of type %v, got %v", p.expectedErrorType, grpcError)
			}
		}
	}
}

var testValidateAuthorizedHeadersParameters = []struct {
	authorizedHeaders    map[string][]string
	metadataHeaders      map[string]string
	expectedErrorType    codes.Code
	expectedMatchedValue string
}{
	// empty is ok
	{nil, nil, codes.OK, ""},
	{map[string][]string{}, map[string]string{}, codes.OK, ""},
	// extra headers ok
	{nil, map[string]string{"H": "V"}, codes.OK, ""},
	// missing header is not ok
	{map[string][]string{"H": {"V"}}, nil, codes.Unauthenticated, ""},
	{map[string][]string{"H": {"V"}}, map[string]string{}, codes.Unauthenticated, ""},
	// authorized value with incorrect header is not ok
	{map[string][]string{"H": {"V"}}, map[string]string{"H1": "V"}, codes.Unauthenticated, ""},
	// correct header, incorrect value is not ok
	{map[string][]string{"H": {"V"}}, map[string]string{"H": "V1"}, codes.Unauthenticated, ""},
	// single header matches
	{map[string][]string{"H": {"V"}}, map[string]string{"H": "V"}, codes.OK, "V"},
	// one match, one missing is ok
	{map[string][]string{"H1": {"V1", "V2"}}, map[string]string{"H1": "V1"}, codes.OK, "V1"},
	// one match, one not match is ok
	{map[string][]string{"H1": {"V1"}, "H2": {"V3"}}, map[string]string{"H1": "V1", "H2": "V2"}, codes.OK, "V1"},
}

func TestValidateAuthorizedHeaders(t *testing.T) {
	for _, p := range testValidateAuthorizedHeadersParameters {
		md := metadata.New(p.metadataHeaders)
		matchedValue, err := validateAuthorizedHeaders(p.authorizedHeaders, md)
		if (p.expectedErrorType != codes.OK) != (err != nil) {
			t.Fatalf("Expected %v, got %v",
				p.expectedErrorType, err)
		}
		if p.expectedErrorType != codes.OK {
			if grpcError, ok := status.FromError(err); grpcError.Code() != p.expectedErrorType || !ok {
				t.Fatalf("Expected error of type %v, got %v", p.expectedErrorType, grpcError)
			}
		} else {
			if matchedValue != p.expectedMatchedValue {
				t.Fatalf("Expected matched value %s, got %s", p.expectedMatchedValue, matchedValue)
			}
		}
	}
}

var testStoreAuditorNameInterceptorErrorParameters = []string{"example2.auditor", ""}

func TestStoreAuditorNameInterceptor_Error(t *testing.T) {
	cfg := &config.ServiceConfig{
		HeaderValueToAuditorName: map[string]string{
			"example1.auditor": "example-auditor-1",
		},
	}

	mockHandler := func(ctx context.Context, req any) (any, error) {
		auditorName, ok := ctx.Value(AuditorNameContextKey).(string)
		if !ok {
			return nil, status.Error(codes.Internal, "auditor name not found in context")
		}
		return auditorName, nil
	}

	for _, invalidHeaderValue := range testStoreAuditorNameInterceptorErrorParameters {
		ctx := context.WithValue(context.Background(), HeaderValueContextKey, invalidHeaderValue)

		interceptor := storeAuditorNameInterceptor(cfg)

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, mockHandler)

		if grpcError, ok := status.FromError(err); grpcError.Code() != codes.InvalidArgument || !ok {
			t.Fatalf("Expected error of type %v, got %v", codes.InvalidArgument, grpcError)
		}
	}
}

func TestStoreAuditorNameInterceptor_Success(t *testing.T) {
	cfg := &config.ServiceConfig{
		HeaderValueToAuditorName: map[string]string{
			"example1.auditor": "example-auditor-1",
		},
	}

	// Mock handler that returns the auditor name from context
	mockHandler := func(ctx context.Context, req any) (any, error) {
		auditorName, ok := ctx.Value(AuditorNameContextKey).(string)
		if !ok {
			return nil, status.Error(codes.Internal, "auditor name not found in context")
		}
		return auditorName, nil
	}

	ctx := context.WithValue(context.Background(), HeaderValueContextKey, "example1.auditor")

	interceptor := storeAuditorNameInterceptor(cfg)

	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, mockHandler)

	assert.NoError(t, err)
	auditorName, ok := resp.(string)
	assert.True(t, ok, "expected string response")
	assert.Equal(t, "example-auditor-1", auditorName)
}

func TestParseRpcMethodString_Success(t *testing.T) {
	service, method, err := parseFullMethodString("/package.service/method")

	assert.NoError(t, err)
	assert.Equal(t, "service", service)
	assert.Equal(t, "method", method)

}

var invalidRpcMethodStrings = []string{
	"/package.service/method/",
	"package.service/method",
	"package.service.method",
	"service/method",
	".service.method",
}

func TestParseRpcMethodString_Failure(t *testing.T) {
	for _, invalidMethodString := range invalidRpcMethodStrings {
		service, method, err := parseFullMethodString(invalidMethodString)

		assert.Error(t, err)
		assert.Empty(t, service)
		assert.Empty(t, method)
	}
}

func TestGetSearchKeyType(t *testing.T) {
	tests := []struct {
		name           string
		searchKeyBytes []byte
		expectedType   string
		expectError    bool
	}{
		{
			name:           "ACI prefix returns AciLabel",
			searchKeyBytes: append([]byte{shared.AciPrefix}, validAci1...),
			expectedType:   AciLabel,
			expectError:    false,
		},
		{
			name:           "UsernameHash prefix returns UsernameHashLabel",
			searchKeyBytes: append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...),
			expectedType:   UsernameHashLabel,
			expectError:    false,
		},
		{
			name:           "Number prefix returns NumberLabel",
			searchKeyBytes: append([]byte{shared.NumberPrefix}, []byte(validPhoneNumber1)...),
			expectedType:   NumberLabel,
			expectError:    false,
		},
		{
			name:           "empty byte slice returns error",
			searchKeyBytes: []byte{},
			expectedType:   "",
			expectError:    true,
		},
		{
			name:           "unrecognized prefix returns error",
			searchKeyBytes: append([]byte{'s'}, validAci1...),
			expectedType:   "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getSearchKeyType(tt.searchKeyBytes)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expectedType {
					t.Errorf("expected type %q, got %q", tt.expectedType, result)
				}
			}
		})
	}
}
