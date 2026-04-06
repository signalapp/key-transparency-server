//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"crypto/subtle"
	"math/rand"
	"strings"
	"time"

	"github.com/hashicorp/go-metrics"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/internal/util"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/transparency"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

type KtQueryHandler struct {
	config    *config.APIConfig
	tx        db.TransparencyStore
	accountDB db.AccountDB

	pb.UnimplementedKeyTransparencyQueryServiceServer
}

func (h *KtQueryHandler) Distinguished(ctx context.Context, req *pb.DistinguishedRequest) (*pb.DistinguishedResponse, error) {
	start := time.Now()
	res, err := h.distinguished(req)
	labels := []metrics.Label{successLabel(err), grpcStatusLabel(err)}
	metrics.IncrCounterWithLabels([]string{"distinguished_requests"}, 1, labels)
	metrics.MeasureSinceWithLabels([]string{"distinguished_duration"}, start, labels)
	if err, _ := status.FromError(err); err.Code() == codes.Unknown {
		util.Log().Errorf("Unexpected search error for distinguished key in key transparency service: %v", err.Err())
	}
	return res, err
}

func (h *KtQueryHandler) distinguished(req *pb.DistinguishedRequest) (*pb.DistinguishedResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	tree, err := h.config.NewTree(h.tx)
	if err != nil {
		return nil, err
	}

	searchReq := &tpb.TreeSearchRequest{
		SearchKey: []byte(distinguishedSearchKey),
		Consistency: &tpb.Consistency{
			Distinguished: req.Last,
		},
	}
	resp, err := tree.Search(searchReq)
	if err != nil {
		return nil, err
	}

	return &pb.DistinguishedResponse{
		TreeHead:      resp.TreeHead,
		Distinguished: convertToCondensedSearchResponse(resp),
	}, nil
}

func (h *KtQueryHandler) Search(ctx context.Context, req *pb.SearchRequest) (*pb.SearchResponse, error) {
	start := time.Now()
	tree, err := h.config.NewTree(h.tx)
	if err != nil {
		return nil, err
	}
	res, err := h.search(req, tree)
	labels := []metrics.Label{successLabel(err), grpcStatusLabel(err)}
	metrics.IncrCounterWithLabels([]string{"search_requests"}, 1, labels)
	metrics.MeasureSinceWithLabels([]string{"search_duration"}, start, labels)

	if err, _ := status.FromError(err); err.Code() == codes.Unknown {
		util.Log().Errorf("Unexpected search error in key transparency service: %v", err.Err())
	}

	// Achieve some minimum delay with jitter on the request to avoid a timing side-channel.
	addRandomDelay(start, time.Now(), h.config.MinimumSearchDelay, h.config.JitterPercent, "search")
	metrics.MeasureSinceWithLabels([]string{"total_search_duration"}, start, labels)
	return res, err
}

// Only ACI searches result in a `NotFound` or `PermissionDenied` response.
// Phone numbers and username hashes that are not found or fail verification will return an empty `TreeSearchResponse`.
func (h *KtQueryHandler) search(req *pb.SearchRequest, tree *transparency.Tree) (*pb.SearchResponse, error) {
	err := validateRequestParameters(req)
	if err != nil {
		return nil, err
	}

	fullTreeHead, aciResponse, err := aciSearch(req, tree)
	if err != nil {
		return nil, err
	}

	usernameHashResponse, err := usernameHashSearch(req, tree)
	if err != nil {
		return nil, err
	}

	phoneNumberResponse, err := h.phoneNumberSearch(req, tree)
	if err != nil {
		return nil, err
	}

	return &pb.SearchResponse{
		TreeHead:     fullTreeHead,
		Aci:          aciResponse,
		UsernameHash: usernameHashResponse,
		E164:         phoneNumberResponse,
	}, nil
}

func validateRequestParameters(req *pb.SearchRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	if len(req.Aci) != 16 {
		return status.Error(codes.InvalidArgument, "invalid ACI")
	}
	if len(req.AciIdentityKey) == 0 {
		return status.Error(codes.InvalidArgument, "must provide ACI identity key")
	}
	if req.E164SearchRequest != nil {
		if len(req.E164SearchRequest.UnidentifiedAccessKey) == 0 {
			return status.Error(codes.InvalidArgument, "must provide unidentified access key for a phone number search")
		}

		if !isPossiblePhoneNumber(req.E164SearchRequest.GetE164()) {
			return status.Error(codes.InvalidArgument, "invalid phone number")
		}
	}
	if len(req.UsernameHash) != 0 && len(req.UsernameHash) != 32 {
		return status.Error(codes.InvalidArgument, "invalid username hash")
	}
	if req.Consistency == nil {
		return status.Error(codes.InvalidArgument, "consistency cannot be nil")
	}
	return nil
}

// Looks up the ACI identifier and verifies that the mapped value matches.
// Other queries will not be allowed to continue unless this one verifies successfully.
func aciSearch(req *pb.SearchRequest, tree *transparency.Tree) (*tpb.FullTreeHead, *pb.CondensedTreeSearchResponse, error) {
	consistency := &tpb.Consistency{
		Last:          req.Consistency.Last,
		Distinguished: req.Consistency.Distinguished,
	}

	aciResponse, err := tree.Search(&tpb.TreeSearchRequest{
		SearchKey:   append([]byte{shared.AciPrefix}, req.Aci...),
		Consistency: consistency,
	})
	metrics.IncrCounterWithLabels([]string{"search_requests", "aci"}, 1, []metrics.Label{grpcStatusLabel(err)})

	if err != nil {
		// There's no use case for distinguishing "not found" vs "permission denied"
		// and consolidating prevents information leakage.
		if grpcError, _ := status.FromError(err); grpcError.Code() == codes.NotFound {
			err = status.Error(codes.PermissionDenied, "provided value does not match expected value")
		}
		return nil, nil, err
	} else if len(aciResponse.Value.Value) < 2 || aciResponse.Value.Value[0] != 0 {
		return nil, nil, status.Error(codes.Internal, "unexpected response value")
	}

	err = verifyMappedValueConstantTime(req.AciIdentityKey, aciResponse.Value.Value[1:])
	if err != nil {
		return nil, nil, err
	}
	fullTreeHead := aciResponse.GetTreeHead()
	return fullTreeHead, convertToCondensedSearchResponse(aciResponse), nil
}

func usernameHashSearch(req *pb.SearchRequest, tree *transparency.Tree) (*pb.CondensedTreeSearchResponse, error) {
	if len(req.UsernameHash) == 0 {
		return nil, nil
	}

	usernameHashResponse, responseErr := tree.Search(&tpb.TreeSearchRequest{
		SearchKey:   append([]byte{shared.UsernameHashPrefix}, req.UsernameHash...),
		Consistency: &tpb.Consistency{},
	})
	metrics.IncrCounterWithLabels([]string{"search_requests", "username_hash"}, 1, []metrics.Label{grpcStatusLabel(responseErr)})

	if responseErr != nil {
		// A non-nil err should be returned except in the case where it's "not found".
		// In that case, we don't respond to the search but still allow a phone number search to continue.
		if grpcError, _ := status.FromError(responseErr); grpcError.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, responseErr
	} else if len(usernameHashResponse.Value.Value) < 2 || usernameHashResponse.Value.Value[0] != 0 {
		return nil, status.Error(codes.Internal, "unexpected response value")
	} else {
		err := verifyMappedValueConstantTime(req.Aci, usernameHashResponse.Value.Value[1:])
		if err != nil {
			// If the ACI doesn't match, don't respond to the search
			// but still allow a phone number search to continue.
			return nil, nil
		}
	}

	return convertToCondensedSearchResponse(usernameHashResponse), nil
}

func (h *KtQueryHandler) phoneNumberSearch(req *pb.SearchRequest, tree *transparency.Tree) (*pb.CondensedTreeSearchResponse, error) {
	if req.E164SearchRequest == nil {
		return nil, nil
	}

	accountData, err := h.accountDB.GetAccountByAci(req.Aci)
	if err != nil {
		return nil, err
	}

	// A non-nil responseErr should be returned except in the case where it's "not found" for a phone number lookup.
	// This is to prevent short-circuiting and creating a timing difference between an account that doesn't exist
	// with the given phone number, and one that does but is undiscoverable.
	phoneNumberResponse, responseErr := tree.Search(&tpb.TreeSearchRequest{
		SearchKey:   append([]byte{shared.NumberPrefix}, []byte(req.E164SearchRequest.GetE164())...),
		Consistency: &tpb.Consistency{},
	})
	metrics.IncrCounterWithLabels([]string{"search_requests", "e164"}, 1, []metrics.Label{grpcStatusLabel(responseErr)})

	var valueForComparison []byte
	if responseErr != nil {
		if grpcError, _ := status.FromError(responseErr); grpcError.Code() == codes.NotFound {
			// Set this value to something that will always fail comparison
			valueForComparison = createDistinctValue(req.Aci)
		} else {
			return nil, responseErr
		}
	} else if len(phoneNumberResponse.Value.Value) < 2 || phoneNumberResponse.Value.Value[0] != 0 {
		return nil, status.Error(codes.Internal, "unexpected response value")
	} else {
		valueForComparison = phoneNumberResponse.Value.Value[1:]
	}

	err = verifyPhoneNumberSearchConstantTime(req.Aci, valueForComparison, req.E164SearchRequest.UnidentifiedAccessKey, accountData)
	if err != nil {
		return nil, nil
	}

	return convertToCondensedSearchResponse(phoneNumberResponse), nil
}

func (h *KtQueryHandler) Monitor(ctx context.Context, req *pb.MonitorRequest) (*pb.MonitorResponse, error) {
	start := time.Now()
	res, err := h.monitor(req)
	labels := []metrics.Label{successLabel(err), grpcStatusLabel(err)}
	metrics.IncrCounterWithLabels([]string{"monitor_requests"}, 1, labels)
	metrics.MeasureSinceWithLabels([]string{"monitor_duration"}, start, labels)
	if err, _ := status.FromError(err); err.Code() == codes.Unknown {
		util.Log().Errorf("Unexpected monitor error in key transparency service: %v", err.Err())
	}
	// Achieve some minimum delay with jitter on the request to avoid a timing side-channel.
	addRandomDelay(start, time.Now(), h.config.MinimumMonitorDelay, h.config.JitterPercent, "monitor")
	metrics.MeasureSinceWithLabels([]string{"total_monitor_duration"}, start, labels)
	return res, err
}

func (h *KtQueryHandler) monitor(req *pb.MonitorRequest) (*pb.MonitorResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	tree, err := h.config.NewTree(h.tx)
	if err != nil {
		return nil, err
	}

	monitorKeys := []*tpb.MonitorKey{
		{
			SearchKey:       append([]byte{shared.AciPrefix}, req.Aci.GetAci()...),
			EntryPosition:   req.Aci.GetEntryPosition(),
			CommitmentIndex: req.Aci.GetCommitmentIndex(),
		},
	}

	if req.GetUsernameHash() != nil {
		monitorKeys = append(monitorKeys, &tpb.MonitorKey{
			SearchKey:       append([]byte{shared.UsernameHashPrefix}, req.UsernameHash.GetUsernameHash()...),
			EntryPosition:   req.UsernameHash.GetEntryPosition(),
			CommitmentIndex: req.UsernameHash.GetCommitmentIndex(),
		})
	}

	if req.GetE164() != nil {
		monitorKeys = append(monitorKeys, &tpb.MonitorKey{
			SearchKey:       append([]byte{shared.NumberPrefix}, req.E164.GetE164()...),
			EntryPosition:   req.E164.GetEntryPosition(),
			CommitmentIndex: req.E164.GetCommitmentIndex(),
		})
	}

	internalMonitorRequest := &tpb.MonitorRequest{
		Keys:        monitorKeys,
		Consistency: req.Consistency,
	}

	internalMonitorResponse, err := tree.Monitor(internalMonitorRequest)

	if err != nil {
		return nil, err
	}

	var aciProof *tpb.MonitorProof
	aciProof, internalMonitorResponse.Proofs = internalMonitorResponse.Proofs[0], internalMonitorResponse.Proofs[1:]

	var usernameHashProof *tpb.MonitorProof
	if req.GetUsernameHash() != nil {
		usernameHashProof, internalMonitorResponse.Proofs = internalMonitorResponse.Proofs[0], internalMonitorResponse.Proofs[1:]
	}

	var e164Proof *tpb.MonitorProof
	if req.GetE164() != nil {
		e164Proof = internalMonitorResponse.Proofs[0]
	}

	return &pb.MonitorResponse{
		TreeHead:     internalMonitorResponse.TreeHead,
		Aci:          aciProof,
		UsernameHash: usernameHashProof,
		E164:         e164Proof,
		Inclusion:    internalMonitorResponse.Inclusion,
	}, nil
}

func isPossiblePhoneNumber(number string) bool {
	if !strings.HasPrefix(number, "+") {
		return false
	} else if len(number[1:]) > 15 {
		// E.164 specifies a maximum of 15 digits
		return false
	}
	return true
}

// Phone number searches must pass additional checks:
// - the account must be discoverable
// - the unidentified access key provided in the request must match the one on the account
func verifyPhoneNumberSearchConstantTime(mappedValue, expectedValue, reqUnidentifiedAccessKey []byte, accountData *db.Account) error {
	var accountUnidentifiedAccessKeyForComparison []byte
	discoverable := 0

	if accountData == nil {
		// If no account exists, set this value to something that will always fail comparison
		accountUnidentifiedAccessKeyForComparison = createDistinctValue(reqUnidentifiedAccessKey)
	} else {
		accountUnidentifiedAccessKeyForComparison = accountData.UnidentifiedAccessKey
		if accountData.DiscoverableByPhoneNumber {
			discoverable = 1
		}
	}

	unidentifiedAccessKeysEqual := 0
	if subtle.ConstantTimeCompare(accountUnidentifiedAccessKeyForComparison, reqUnidentifiedAccessKey) == 1 {
		unidentifiedAccessKeysEqual = 1
	}

	if (discoverable & unidentifiedAccessKeysEqual) == 0 {
		// We want to avoid leaking data about the existence of an account with a given phone number
		return status.Error(codes.NotFound, "user not found")
	}

	return verifyMappedValueConstantTime(mappedValue, expectedValue)
}

func convertToCondensedSearchResponse(response *tpb.TreeSearchResponse) *pb.CondensedTreeSearchResponse {
	return &pb.CondensedTreeSearchResponse{
		VrfProof: response.VrfProof,
		Search:   response.Search,
		Opening:  response.Opening,
		Value:    response.Value,
	}
}

// addJitter adds random jitter to the specified duration and returns the final duration.
// For example, if the minDelay is 1000ms and the jitterPercent is 10, addJitter will
// return a random duration in the interval [1000ms, 1100ms].
func addJitter(minDelay time.Duration, jitterPercent int) time.Duration {
	upperBound := float64(minDelay.Nanoseconds()) * float64(jitterPercent) / 100.0

	// Generate a random value between [0, upperBound]
	jitter := rand.Int63n(int64(upperBound) + 1)

	return minDelay + time.Duration(jitter)
}

// addRandomDelay injects a delay to achieve some minimum jittered delay for the request.
func addRandomDelay(start, now time.Time, minDelay time.Duration, jitterPercent int, endpoint string) {
	elapsed := now.Sub(start)
	jitteredMinDelay := addJitter(minDelay, jitterPercent)
	timeToSleep := jitteredMinDelay - elapsed
	metrics.AddSampleWithLabels([]string{"random_delay_duration"}, float32(timeToSleep.Nanoseconds())/float32(time.Millisecond), []metrics.Label{endpointLabel(endpoint)})

	if timeToSleep < 0 {
		metrics.IncrCounterWithLabels([]string{"elapsed_greater_than_min_delay"}, 1, []metrics.Label{endpointLabel(endpoint)})
		metrics.AddSampleWithLabels([]string{"negative_random_delay_duration"}, float32(timeToSleep.Nanoseconds())/float32(time.Millisecond), []metrics.Label{endpointLabel(endpoint)})
	}

	time.Sleep(timeToSleep)
}
