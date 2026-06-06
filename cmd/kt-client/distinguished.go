//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"

	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/tree/transparency"
)

func handleDistinguished(client pb.KeyTransparencyQueryServiceClient) {
	req := new(pb.DistinguishedRequest)
	if *last >= 0 {
		x := uint64(*last)
		req.Last = &x
	}
	res, err := client.Distinguished(context.Background(), req)
	checkErr("distinguished request", err)

	printFullTreeHead(res.TreeHead)
	p.Printf("Distinguished search response: \n")
	p.Printf("VRF: %x\n\n", res.Distinguished.VrfProof)
	printSearchProof(res.Distinguished.Search)
	p.Printf("Opening: %x\n", res.Distinguished.Opening)
	p.Printf("Value: %s\n\n", res.Distinguished.Value.Value)

	if *configFile == "" {
		p.Printf("Verification skipped\n")
	} else {
		if *last != -1 {
			// Verifying the consistency proof would require persistent state, which kt-client doesn't have,
			// so we nullify these fields.
			removeConsistencyProofsForStatelessVerification(res.TreeHead)
		}
		if err := transparency.VerifySearch(newStore(), createTreeSearchRequest([]byte("distinguished")), createTreeSearchResponse(res.Distinguished, res.TreeHead)); err != nil {
			p.Printf("Verification failed: %v\n", err)
		} else {
			p.Printf("Verification successful\n")
		}
	}
}
