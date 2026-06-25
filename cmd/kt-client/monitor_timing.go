//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"fmt"

	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
)

func handleMonitorTiming(client pb.KeyTransparencyQueryServiceClient) {
	args := extractQueryArgs("[-sample-size int] [-num-samples int] monitor-timing")
	samplingArgs := extractSamplingArgs()

	// First search the identifiers to get back the data necessary to make a monitor request
	searchResponseV2, err := client.SearchV2(context.Background(), constructSearchRequest(args))

	checkErr("Search identifiers before making a monitor request", err)
	fmt.Println("Search request: OK")
	fmt.Printf("Measuring latency for monitoring ACI %x and E164 %s (%d rounds, %d requests per round)\n", args.Aci, *e164, samplingArgs.NumSamples, samplingArgs.SampleSize)

	vrfVerifier := newStore().PublicConfig().VrfKey

	searchResponse := extractSearchResponse(searchResponseV2)
	req := constructMonitorRequest(args, vrfVerifier, searchResponse)
	timeRequest(func() error {
		_, err := client.MonitorV2(context.Background(), req)
		return err
	}, samplingArgs)
}
