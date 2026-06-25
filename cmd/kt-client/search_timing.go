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

func handleSearchTiming(client pb.KeyTransparencyQueryServiceClient) {
	args := extractQueryArgs("[-sample-size int] [-num-samples int] search-timing")
	samplingArgs := extractSamplingArgs()

	fmt.Printf("Measuring latency for searching ACI %x and E164 %s (%d rounds, %d requests per round)\n", args.Aci, *e164, samplingArgs.NumSamples, samplingArgs.SampleSize)
	req := constructSearchRequest(args)

	timeRequest(func() error {
		_, err := client.SearchV2(context.Background(), req)
		return err
	}, samplingArgs)
}
