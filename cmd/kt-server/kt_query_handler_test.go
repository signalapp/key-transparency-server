//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/db"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

var (
	mockConfigFile                  = "test_config.yaml"
	validUsernameHash1              = random(32)
	validPhoneNumber1               = "+14155550101"
	unidentifiedAccessKey           = random(16)
	mismatchedUnidentifiedAccessKey = createDistinctValue(unidentifiedAccessKey)

	invalidAci          = make([]byte, 15)
	invalidUsernameHash = random(31)
	invalidPhoneNumber1 = "14155550101"
	invalidPhoneNumber2 = "+1415555010101456"
)

func TestDistinguished_NilRequest(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	_, err := h.distinguished(nil)
	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.InvalidArgument || !ok {
		t.Fatalf("Expected %v, got %v",
			codes.InvalidArgument, err)
	}
}

var testInvalidSearchRequestParameters = []struct {
	searchRequest *pb.SearchRequest
}{
	// Nil search request
	{nil},
	// No aci
	{&pb.SearchRequest{AciIdentityKey: validAciIdentityKey1, Consistency: &tpb.Consistency{}}},
	// ACI wrong length
	{&pb.SearchRequest{Aci: invalidAci, AciIdentityKey: validAciIdentityKey1, Consistency: &tpb.Consistency{}}},
	// No ACI identity key
	{&pb.SearchRequest{Aci: validAci1, Consistency: &tpb.Consistency{}}},
	// Phone number search with no phone number or unidentified access key
	{&pb.SearchRequest{Aci: invalidAci, AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{}, Consistency: &tpb.Consistency{}}},
	// Phone number search key with no unidentified access key
	{&pb.SearchRequest{Aci: invalidAci, AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{E164: &validPhoneNumber1},
		Consistency:       &tpb.Consistency{}}},
	// Phone number search key missing leading '+'
	{&pb.SearchRequest{Aci: invalidAci, AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{E164: &invalidPhoneNumber1, UnidentifiedAccessKey: unidentifiedAccessKey},
		Consistency:       &tpb.Consistency{}}},
	// Phone number search key with invalid length
	{&pb.SearchRequest{Aci: invalidAci, AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{E164: &invalidPhoneNumber2, UnidentifiedAccessKey: unidentifiedAccessKey},
		Consistency:       &tpb.Consistency{}}},
	// Username hash search key with invalid length
	{&pb.SearchRequest{Aci: validAci1, AciIdentityKey: validAciIdentityKey1,
		UsernameHash: invalidUsernameHash, Consistency: &tpb.Consistency{}}},
	// Consistency cannot be nil
	{&pb.SearchRequest{Aci: validAci1, AciIdentityKey: validAciIdentityKey1}},
	// Consistency cannot be nil
	{&pb.SearchRequest{Aci: validAci1, AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{E164: &validPhoneNumber1, UnidentifiedAccessKey: unidentifiedAccessKey}}},
}

func TestSearch_InvalidArgument(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	for _, p := range testInvalidSearchRequestParameters {
		_, err := h.search(p.searchRequest, tree)
		if grpcError, ok := status.FromError(err); grpcError.Code() != codes.InvalidArgument || !ok {
			t.Fatalf("Expected %v, got %v",
				codes.InvalidArgument, err)
		}
	}
}

func TestSearch_AciNotFound(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	// Add ACI so that we're not searching an empty tree
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, validAci1...),
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree, %v", err)
	}

	// Search for a different ACI
	resp, err := h.search(&pb.SearchRequest{
		Aci:            random(16),
		AciIdentityKey: validAciIdentityKey1,
		Consistency:    &tpb.Consistency{},
	}, tree)
	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.PermissionDenied || !ok {
		t.Fatalf("Expected %v, got %v",
			codes.PermissionDenied, err)
	} else if resp != nil {
		t.Fatalf("Expected no search response")
	}
}

func TestSearch_AciPermissionDenied(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	// Add ACI
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, validAci1...),
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Search for the same ACI, but provide the wrong ACI identity key
	searchReq := &pb.SearchRequest{
		Aci:            validAci1,
		AciIdentityKey: mismatchedUnidentifiedAccessKey,
		Consistency:    &tpb.Consistency{},
	}

	resp, err := h.search(searchReq, tree)
	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.PermissionDenied || !ok {
		t.Fatalf("Expected %v, got %v",
			codes.PermissionDenied, err)
	} else if resp != nil {
		t.Fatalf("Expected no search response")
	}
}

func TestSearch_UsernameHashNotFound(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	// Add ACI so that we're not searching an empty tree
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, validAci1...),
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Search for ACI and non-existent username hash
	searchReq := &pb.SearchRequest{
		Aci:            validAci1,
		AciIdentityKey: validAciIdentityKey1,
		UsernameHash:   validUsernameHash1,
		Consistency:    &tpb.Consistency{},
	}

	resp, err := h.search(searchReq, tree)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	} else if resp == nil || resp.Aci == nil {
		t.Fatalf("Expected ACI search response")
	} else if resp.TreeHead == nil {
		t.Fatalf("Expected top-level tree head")
	} else if resp.UsernameHash != nil {
		t.Fatalf("Expected no username hash search response")
	}
}

func TestSearch_E164NotFound(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	// Add ACI so that we're not searching an empty tree
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, validAci1...),
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Search for ACI and non-existent E164
	resp, err := h.search(&pb.SearchRequest{
		Aci:            validAci1,
		AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{
			E164:                  &validPhoneNumber1,
			UnidentifiedAccessKey: unidentifiedAccessKey,
		},
		Consistency: &tpb.Consistency{},
	}, tree)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	} else if resp == nil || resp.Aci == nil {
		t.Fatalf("Expected an ACI search response")
	} else if resp.TreeHead == nil {
		t.Fatalf("Expected a top-level tree head")
	} else if resp.E164 != nil {
		t.Fatalf("Expected no E164 search response")
	}
}

func TestSearch_E164DoesNotMatch(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	// Add ACI
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, validAci1...),
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Add username hash
	usernameHashUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...),
		Value:       append([]byte{0}, validAci1...),
		Consistency: &tpb.Consistency{},
	}
	_, err = tree.UpdateSimple(usernameHashUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Add E164 that maps to a different ACI
	e164UpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.NumberPrefix}, []byte(validPhoneNumber1)...),
		Value:       append([]byte{0}, mismatchedAci...),
		Consistency: &tpb.Consistency{},
	}
	_, err = tree.UpdateSimple(e164UpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Search for ACI and E164. Provide the wrong ACI for the E164.
	searchReq := &pb.SearchRequest{
		Aci:            validAci1,
		AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{
			E164:                  &validPhoneNumber1,
			UnidentifiedAccessKey: unidentifiedAccessKey,
		},
		UsernameHash: validUsernameHash1,
		Consistency:  &tpb.Consistency{},
	}

	resp, err := h.search(searchReq, tree)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	} else if resp == nil || resp.Aci == nil || resp.UsernameHash == nil {
		t.Fatalf("Expected ACI and username hash search responses")
	} else if resp.TreeHead == nil {
		t.Fatalf("Expected ACI search response to have tree head")
	} else if resp.E164 != nil {
		t.Fatalf("Expected no E164 search response")
	}
}

func TestSearch_UsernameHashDoesNotMatch(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	// Add ACI
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, validAci1...),
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Add E164
	e164UpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.NumberPrefix}, []byte(validPhoneNumber1)...),
		Value:       append([]byte{0}, validAci1...),
		Consistency: &tpb.Consistency{},
	}
	_, err = tree.UpdateSimple(e164UpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Add username hash that maps to a different ACI
	usernameHashUpdateReq := &tpb.UpdateRequest{
		SearchKey:   append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...),
		Value:       append([]byte{0}, mismatchedAci...),
		Consistency: &tpb.Consistency{},
	}
	_, err = tree.UpdateSimple(usernameHashUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree")
	}

	// Search for all three identifiers
	searchReq := &pb.SearchRequest{
		Aci:            validAci1,
		AciIdentityKey: validAciIdentityKey1,
		E164SearchRequest: &pb.E164SearchRequest{
			E164:                  &validPhoneNumber1,
			UnidentifiedAccessKey: db.UnidentifiedAccessKey,
		},
		UsernameHash: validUsernameHash1,
		Consistency:  &tpb.Consistency{},
	}

	resp, err := h.search(searchReq, tree)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	} else if resp == nil || resp.Aci == nil || resp.E164 == nil {
		t.Fatalf("Expected ACI and E164 search responses")
	} else if resp.TreeHead == nil {
		t.Fatalf("Expected top-level tree head")
	} else if resp.UsernameHash != nil {
		t.Fatalf("Expected no username hash search response")
	}
}

var testInvalidMonitorParameters = []struct {
	monitorRequest *pb.MonitorRequest
	expectedError  codes.Code
}{
	// nil monitor request
	{nil, codes.InvalidArgument},
	// aci monitor request must not be nil
	{&pb.MonitorRequest{}, codes.InvalidArgument},
	// aci.Aci must not be nil
	{&pb.MonitorRequest{
		Aci: &pb.AciMonitorRequest{},
	}, codes.InvalidArgument},
	// aci.Entries must not be nil
	{&pb.MonitorRequest{
		Aci: &pb.AciMonitorRequest{Aci: validAci1},
	}, codes.InvalidArgument},
	// aci.CommitmentIndex must not be nil
	{&pb.MonitorRequest{
		Aci: &pb.AciMonitorRequest{Aci: validAci1, EntryPosition: 0},
	}, codes.InvalidArgument},
	// aci.CommitmentIndex must be of length 32
	{&pb.MonitorRequest{
		Aci: &pb.AciMonitorRequest{Aci: validAci1, EntryPosition: 0, CommitmentIndex: []byte{0}},
	}, codes.InvalidArgument},
	// aci.CommitmentIndex does not match
	{&pb.MonitorRequest{
		Aci: &pb.AciMonitorRequest{Aci: validAci1, EntryPosition: 0, CommitmentIndex: make([]byte, 32)}},
		codes.PermissionDenied},
}

func TestMonitor_InvalidRequests(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	for _, p := range testInvalidMonitorParameters {
		_, err := h.monitor(p.monitorRequest)

		if p.expectedError != codes.OK {
			if grpcError, ok := status.FromError(err); grpcError.Code() != p.expectedError || !ok {
				t.Fatalf("Expected error of type %v, got %v", p.expectedError, grpcError)
			}
		}
	}
}

func TestMonitor(t *testing.T) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	accountDb := db.MockAccountDB{}
	h := KtQueryHandler{config: mockConfig.APIConfig, tx: mockTransparencyStore, accountDB: &accountDb}

	tree, _ := mockConfig.APIConfig.NewTree(mockTransparencyStore)

	// Setup part 1: add data so that we're not using an empty tree

	aciSearchKey := append([]byte{shared.AciPrefix}, validAci1...)
	aciUpdateReq := &tpb.UpdateRequest{
		SearchKey:   aciSearchKey,
		Value:       append([]byte{0}, validAciIdentityKey1...),
		Consistency: &tpb.Consistency{},
	}
	_, err := tree.UpdateSimple(aciUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree, %v", err)
	}

	usernameHashSearchKey := append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...)
	usernameHashUpdateReq := &tpb.UpdateRequest{
		SearchKey:   usernameHashSearchKey,
		Value:       append([]byte{0}, validAci1...),
		Consistency: &tpb.Consistency{},
	}
	_, err = tree.UpdateSimple(usernameHashUpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree, %v", err)
	}

	e164SearchKey := append([]byte{shared.NumberPrefix}, validPhoneNumber1...)
	e164UpdateReq := &tpb.UpdateRequest{
		SearchKey:   e164SearchKey,
		Value:       append([]byte{0}, validAci1...),
		Consistency: &tpb.Consistency{},
	}
	_, err = tree.UpdateSimple(e164UpdateReq)
	if err != nil {
		t.Fatalf("Unexpected error updating the tree, %v", err)
	}

	// Setup part 2: Search, to get a valid commitment index

	searchResponse, err := h.search(&pb.SearchRequest{
		Aci:            validAci1,
		AciIdentityKey: validAciIdentityKey1,
		UsernameHash:   validUsernameHash1,
		E164SearchRequest: &pb.E164SearchRequest{
			E164:                  &validPhoneNumber1,
			UnidentifiedAccessKey: db.UnidentifiedAccessKey,
		},
		Consistency: &tpb.Consistency{},
	}, tree)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	aciCommitmentIndex, err := mockConfig.APIConfig.TreeConfig().Public().VrfKey.ECVRFVerify(aciSearchKey, searchResponse.Aci.VrfProof)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	usernameHashCommitmentIndex, err := mockConfig.APIConfig.TreeConfig().Public().VrfKey.ECVRFVerify(usernameHashSearchKey, searchResponse.UsernameHash.VrfProof)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	e164CommitmentIndex, err := mockConfig.APIConfig.TreeConfig().Public().VrfKey.ECVRFVerify(e164SearchKey, searchResponse.E164.VrfProof)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	// test 1: just ACI

	req := &pb.MonitorRequest{
		Aci: &pb.AciMonitorRequest{
			Aci:             validAci1,
			EntryPosition:   searchResponse.Aci.Search.Pos,
			CommitmentIndex: aciCommitmentIndex[:],
		},
		Consistency: &tpb.Consistency{},
	}

	res, err := h.monitor(req)

	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.OK || !ok {
		t.Fatalf("Unexpected error %v", grpcError)
	}

	if res.Aci == nil {
		t.Fatalf("ACI proof should not be nil")
	}
	if res.UsernameHash != nil {
		t.Fatalf("Username hash proof should be nil")
	}
	if res.E164 != nil {
		t.Fatalf("E164 proof should be nil")
	}
	if len(res.Inclusion) == 0 {
		t.Fatalf("Inclusion proof should not be empty")
	}

	// test 2: ACI + Username Hash

	req.UsernameHash = &pb.UsernameHashMonitorRequest{
		UsernameHash:    validUsernameHash1,
		EntryPosition:   searchResponse.UsernameHash.Search.Pos,
		CommitmentIndex: usernameHashCommitmentIndex[:],
	}

	res, err = h.monitor(req)

	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.OK || !ok {
		t.Fatalf("Unexpected error %v", grpcError)
	}

	if res.Aci == nil {
		t.Fatalf("ACI proof should not be nil")
	}
	if res.UsernameHash == nil {
		t.Fatalf("Username hash proof should not be nil")
	}
	if res.E164 != nil {
		t.Fatalf("E164 proof should be nil")
	}
	if len(res.Inclusion) == 0 {
		t.Fatalf("Inclusion proof should not be empty")
	}

	// test 3: ACI + Username Hash + E164

	req.E164 = &pb.E164MonitorRequest{
		E164:            &validPhoneNumber1,
		EntryPosition:   searchResponse.E164.Search.Pos,
		CommitmentIndex: e164CommitmentIndex[:],
	}

	res, err = h.monitor(req)

	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.OK || !ok {
		t.Fatalf("Unexpected error %v", grpcError)
	}

	if res.Aci == nil {
		t.Fatalf("ACI proof should not be nil")
	}
	if res.UsernameHash == nil {
		t.Fatalf("Username hash proof should not be nil")
	}
	if res.E164 == nil {
		t.Fatalf("E164 proof should not be nil")
	}
	if len(res.Inclusion) == 0 {
		t.Fatalf("Inclusion proof should not be empty")
	}

	// test 4: ACI + E164

	req.UsernameHash = nil

	res, err = h.monitor(req)

	if grpcError, ok := status.FromError(err); grpcError.Code() != codes.OK || !ok {
		t.Fatalf("Unexpected error %v", grpcError)
	}

	if res.Aci == nil {
		t.Fatalf("ACI proof should not be nil")
	}
	if res.UsernameHash != nil {
		t.Fatalf("Username hash proof should be nil")
	}
	if res.E164 == nil {
		t.Fatalf("E164 proof should not be nil")
	}
	if len(res.Inclusion) == 0 {
		t.Fatalf("Inclusion proof should not be empty")
	}
}

var testVerifyPhoneNumberSearchParameters = []struct {
	providedValue         []byte
	expectedValue         []byte
	unidentifiedAccessKey []byte
	account               *db.Account
	expectedErrorType     codes.Code
}{
	// Discoverable; unidentified access key matches; provided value matches; no error
	{validAci1, validAci1, unidentifiedAccessKey, &db.Account{
		UnidentifiedAccessKey:     unidentifiedAccessKey,
		DiscoverableByPhoneNumber: true,
	}, codes.OK},
	// Account does not exist; expect error
	{validAci1, validAci1, unidentifiedAccessKey, nil, codes.NotFound},
	// User not discoverable by phone number; expect error
	{validAci1, validAci1, unidentifiedAccessKey, &db.Account{
		UnidentifiedAccessKey:     unidentifiedAccessKey,
		DiscoverableByPhoneNumber: false,
	}, codes.NotFound},
	// Unidentified access key does not match; expect error
	{validAci1, validAci1, unidentifiedAccessKey, &db.Account{
		UnidentifiedAccessKey:     mismatchedUnidentifiedAccessKey,
		DiscoverableByPhoneNumber: true,
	}, codes.NotFound},
	// Provided and expected mapped values do not match; expect error
	{validAci1, mismatchedAci, unidentifiedAccessKey, &db.Account{
		UnidentifiedAccessKey:     unidentifiedAccessKey,
		DiscoverableByPhoneNumber: true,
	}, codes.PermissionDenied},
}

func TestVerifyPhoneNumberSearchConstantTime(t *testing.T) {
	for _, p := range testVerifyPhoneNumberSearchParameters {
		err := verifyPhoneNumberSearchConstantTime(p.providedValue, p.expectedValue, p.unidentifiedAccessKey, p.account)
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

func TestAddJitter(t *testing.T) {
	for i := 0; i < 100; i++ {
		jitteredVal := addJitter(1000, 10)
		if jitteredVal < 1000 || jitteredVal > 1100 {
			t.Errorf("Jittered value outside expected range [1000, 1100]")
		}
	}
}

func TestAddRandomDelay(t *testing.T) {
	start := time.Now()

	// The request took 50 milliseconds, but require a minimum delay of 100 milliseconds.
	requestTime := 50 * time.Millisecond
	minDelay := 100 * time.Millisecond
	jitterPercent := 10
	maxJitter := time.Duration((float64(jitterPercent) / 100.0) * float64(minDelay))
	buffer := 10 * time.Millisecond

	for i := 0; i < 50; i++ {
		testStart := time.Now()
		addRandomDelay(start, start.Add(requestTime), minDelay, jitterPercent, "test")
		testDuration := time.Since(testStart)
		if testDuration < minDelay-requestTime {
			t.Errorf("Expected at least %v delay, got %v instead", minDelay-requestTime, testDuration)
		}
		if testDuration > minDelay-requestTime+maxJitter+buffer {
			t.Errorf("Expected at most %v delay, got %v instead", minDelay-requestTime+maxJitter+buffer, testDuration)
		}
	}
}
