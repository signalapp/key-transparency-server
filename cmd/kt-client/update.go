//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"

	"github.com/google/uuid"
	"github.com/signalapp/keytransparency/cmd/kt-server/pb"
	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/tree/transparency"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
)

func handleUpdate(client pb.KeyTransparencyTestServiceClient) {
	var updateKey []byte
	var updateValue []byte
	switch flag.Arg(1) {
	case "aci":
		if flag.Arg(2) == "" {
			log.Fatal("No update key given. Usage: kt-client update aci <UUID> <base64_encoded_aci_identity_key>")
		} else if flag.Arg(3) == "" {
			log.Fatal("No update value given. Usage: kt-client update aci <UUID> <base64_encoded_aci_identity_key>")
		}
		aci, err := uuid.Parse(flag.Arg(2))
		checkErr("invalid UUID string for ACI", err)

		aciBytes, err := aci.MarshalBinary()
		checkErr("getting UUID bytes", err)

		updateKey = append([]byte{shared.AciPrefix}, aciBytes...)

		aciIdentityKeyBytes, err := base64.StdEncoding.DecodeString(flag.Arg(3))
		checkErr("decoding base64 encoding for ACI identity key", err)

		updateValue = append([]byte{0}, aciIdentityKeyBytes...)
	case "e164":
		if flag.Arg(2) == "" {
			log.Fatal("No update key given. Usage: kt-client update e164 <e164_string> <UUID>")
		} else if flag.Arg(3) == "" {
			log.Fatal("No update value given. Usage: kt-client update e164 <e164_string> <UUID>")
		}
		updateKey = append([]byte{shared.NumberPrefix}, []byte(flag.Arg(2))...)

		aci, err := uuid.Parse(flag.Arg(3))
		checkErr("invalid UUID string for ACI", err)

		aciBytes, err := aci.MarshalBinary()
		checkErr("getting UUID bytes", err)

		updateValue = append([]byte{0}, aciBytes...)
	case "username_hash":
		if flag.Arg(2) == "" {
			log.Fatal("No update key given. Usage: kt-client update username_hash <base64url_encoded_username_hash> <UUID>")
		} else if flag.Arg(3) == "" {
			log.Fatal("No update value given. Usage: kt-client update username_hash <base64url_encoded_username_hash> <UUID>")
		}
		usernameHashBytes, err := base64.URLEncoding.DecodeString(flag.Arg(2))
		checkErr("decoding base64url encoding for username hash", err)

		updateKey = append([]byte{shared.UsernameHashPrefix}, usernameHashBytes...)

		aci, err := uuid.Parse(flag.Arg(3))
		checkErr("invalid UUID string for ACI", err)

		aciBytes, err := aci.MarshalBinary()
		checkErr("getting UUID bytes", err)

		updateValue = append([]byte{0}, aciBytes...)
	}

	req := &tpb.UpdateRequest{
		SearchKey:            updateKey,
		Value:                updateValue,
		Consistency:          consistency(last),
		ReturnUpdateResponse: true,
	}
	res, err := client.Update(context.Background(), req)
	checkErr("update request", err)

	printFullTreeHead(res.TreeHead)
	p.Printf("VRF: %x\n\n", res.VrfProof)
	printSearchProof(res.Search)
	p.Printf("Opening: %x\n\n", res.Opening)

	if *configFile == "" {
		p.Printf("Verification skipped\n")
	} else {
		// Verifying the consistency proof would require persistent state, which kt-client doesn't have,
		// so we nullify these fields.
		if *last != -1 {
			req.Consistency = nil
			removeConsistencyProofsForStatelessVerification(res.TreeHead)
		}
		if err := transparency.VerifyUpdate(newStore(), req, res); err != nil {
			p.Printf("Verification failed: %v\n", err)
		} else {
			p.Printf("Verification successful\n")
		}
	}
}
