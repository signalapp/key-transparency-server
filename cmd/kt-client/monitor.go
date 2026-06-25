//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"

	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/crypto/vrf"
)

func constructMonitorRequest(args QueryArgs, vrfVerifier vrf.PublicKey, searchResponse *pb.SearchResponse) *pb.MonitorRequest {
	monitorRequest := &pb.MonitorRequest{
		Consistency: consistency(last),
	}

	aciCommitmentIndex, err := vrfVerifier.ECVRFVerify(append([]byte{'a'}, args.Aci...), searchResponse.Aci.VrfProof)
	checkErr("create aci commitment index", err)

	monitorRequest.Aci = &pb.AciMonitorRequest{
		Aci:             args.Aci,
		EntryPosition:   searchResponse.GetAci().GetSearch().GetPos(),
		CommitmentIndex: aciCommitmentIndex[:],
	}

	if searchResponse.E164 != nil {
		e164CommitmentIndex, err := vrfVerifier.ECVRFVerify(append([]byte{'n'}, []byte(args.E164)...), searchResponse.E164.VrfProof)
		checkErr("create e164 commitment index", err)
		monitorRequest.E164 = &pb.E164MonitorRequest{
			E164:            &args.E164,
			EntryPosition:   searchResponse.GetE164().GetSearch().GetPos(),
			CommitmentIndex: e164CommitmentIndex[:],
		}
	}

	if searchResponse.UsernameHash != nil {
		usernameHashCommitmentIndex, err := vrfVerifier.ECVRFVerify(append([]byte{'u'}, args.UsernameHash...), searchResponse.UsernameHash.VrfProof)
		checkErr("create username hash commitment index", err)
		monitorRequest.UsernameHash = &pb.UsernameHashMonitorRequest{
			UsernameHash:    args.UsernameHash,
			EntryPosition:   searchResponse.GetUsernameHash().GetSearch().GetPos(),
			CommitmentIndex: usernameHashCommitmentIndex[:],
		}
	}
	return monitorRequest
}

// handleMonitor makes 2 requests in succession:
//  1. Search request for the specified identifiers to get the commitment index necessary for the monitor request
//  2. Monitor request
func handleMonitor(client pb.KeyTransparencyQueryServiceClient) {
	args := extractQueryArgs("monitor")

	// First search the identifiers to get back the data necessary to make a monitor request
	searchResponseV2, err := client.SearchV2(context.Background(), constructSearchRequest(args))
	checkErr("search identifiers before making a monitor request", err)
	searchResponse := extractSearchResponse(searchResponseV2)
	fmt.Println("Search request: OK")

	vrfVerifier := newStore().PublicConfig().VrfKey
	monitorResponseV2, err := client.MonitorV2(context.Background(), constructMonitorRequest(args, vrfVerifier, searchResponse))
	checkErr("monitor request", err)

	if monitorResponseV2.GetPermissionDenied() != nil {
		_, _ = os.Stderr.WriteString("monitor permission denied")
		os.Exit(1)
	}
	monitorResponse := monitorResponseV2.GetMonitorResponse()

	if monitorResponse == nil {
		_, _ = os.Stderr.WriteString("nil monitor response")
		os.Exit(1)
	}

	printFullTreeHead(monitorResponse.TreeHead)
	p.Println("ACI monitor response:")
	p.Println("Steps: ")
	for _, step := range monitorResponse.Aci.Steps {
		p.Printf("  - counter=%v commitment=%x\n", step.Prefix.Counter, step.Commitment)
	}

	if monitorResponse.E164 != nil {
		p.Println("\nE164 monitor response:")
		p.Println("Steps: ")
		for _, step := range monitorResponse.E164.Steps {
			p.Printf("  - counter=%v commitment=%x\n", step.Prefix.Counter, step.Commitment)
		}
	}

	if monitorResponse.UsernameHash != nil {
		p.Println("\nUsername hash monitor response:")
		p.Println("Steps: ")
		for _, step := range monitorResponse.UsernameHash.Steps {
			p.Printf("  - counter=%v commitment=%x\n", step.Prefix.Counter, step.Commitment)
		}
	}

	// Verifying the monitor response would require persistent state, which kt-client doesn't have,
	// so we skip it.
	p.Println("\nVerification skipped for the monitor response.")
}
