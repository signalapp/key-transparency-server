//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"encoding/base64"

	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/tree/transparency"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

func constructSearchRequest(args QueryArgs) *pb.SearchRequest {
	req := &pb.SearchRequest{
		Aci:            args.Aci,
		AciIdentityKey: args.AciIdentityKey,
		Consistency:    consistency(last),
	}

	if args.E164 != "" {
		req.E164SearchRequest = &pb.E164SearchRequest{
			E164:                  &args.E164,
			UnidentifiedAccessKey: args.UnidentifiedAccessKey,
		}
	}

	if args.UsernameHash != nil {
		req.UsernameHash = args.UsernameHash
	}
	return req
}

func handleSearch(client pb.KeyTransparencyQueryServiceClient) {
	args := extractQueryArgs("search")
	res, err := client.Search(context.Background(), constructSearchRequest(args))
	checkErr("search request", err)

	printFullTreeHead(res.TreeHead)
	p.Printf("ACI search response: \n")

	p.Printf("VRF: %x\n\n", res.Aci.VrfProof)
	printSearchProof(res.Aci.Search)
	p.Printf("Opening: %x\n", res.Aci.Opening)
	p.Printf("Value: %s\n\n", base64.StdEncoding.EncodeToString(res.Aci.Value.Value[1:]))

	if res.E164 != nil {
		p.Printf("E164 search response: \n")

		p.Printf("VRF: %x\n\n", res.E164.VrfProof)
		printSearchProof(res.E164.Search)
		p.Printf("Opening: %x\n", res.E164.Opening)
		p.Printf("Value: %x\n\n", res.E164.Value.Value[1:])
	}

	if res.UsernameHash != nil {
		p.Printf("Username hash search response: \n")

		p.Printf("VRF: %x\n\n", res.UsernameHash.VrfProof)
		printSearchProof(res.UsernameHash.Search)
		p.Printf("Opening: %x\n", res.UsernameHash.Opening)
		p.Printf("Value: %x\n\n", res.UsernameHash.Value.Value[1:])
	}

	if *configFile == "" {
		p.Printf("Verification skipped\n")
		return
	}

	if *last != -1 {
		// Verifying the consistency proof would require persistent state, which kt-client doesn't have,
		// so we nullify these fields.
		removeConsistencyProofsForStatelessVerification(res.TreeHead)
	}

	allVerificationsSuccessful := true
	if err := transparency.VerifySearch(newStore(), createIdentifierSearchRequest(shared.AciPrefix, args.Aci), createTreeSearchResponse(res.Aci, res.TreeHead)); err != nil {
		p.Printf("ACI verification failed: %v\n", err)
		allVerificationsSuccessful = false
	}

	if res.E164 != nil {
		if err := transparency.VerifySearch(newStore(), createIdentifierSearchRequest(shared.NumberPrefix, []byte(*e164)), createTreeSearchResponse(res.E164, res.TreeHead)); err != nil {
			p.Printf("E164 verification failed: %v\n", err)
			allVerificationsSuccessful = false
		}
	}

	if res.UsernameHash != nil {
		if err := transparency.VerifySearch(newStore(), createIdentifierSearchRequest(shared.UsernameHashPrefix, args.UsernameHash), createTreeSearchResponse(res.UsernameHash, res.TreeHead)); err != nil {
			p.Printf("Username hash verification failed: %v\n", err)
			allVerificationsSuccessful = false
		}
	}

	if allVerificationsSuccessful {
		p.Printf("All verifications successful\n")
	}
}

func createIdentifierSearchRequest(prefix byte, identifier []byte) *tpb.TreeSearchRequest {
	return createTreeSearchRequest(append([]byte{prefix}, identifier...))
}

func createTreeSearchRequest(key []byte) *tpb.TreeSearchRequest {
	return &tpb.TreeSearchRequest{
		SearchKey:   key,
		Consistency: consistency(last),
	}
}

func removeConsistencyProofsForStatelessVerification(treeHead *tpb.FullTreeHead) {
	if treeHead == nil {
		return
	}
	treeHead.Last = nil
	treeHead.Distinguished = nil
}

func createTreeSearchResponse(response *pb.CondensedTreeSearchResponse, treeHead *tpb.FullTreeHead) *tpb.TreeSearchResponse {
	return &tpb.TreeSearchResponse{
		TreeHead: treeHead,
		VrfProof: response.VrfProof,
		Search:   response.Search,
		Opening:  response.Opening,
		Value:    response.Value,
	}
}
