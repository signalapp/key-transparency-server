//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"strings"
	"testing"

	"github.com/signalapp/keytransparency/tree/transparency"
	tpb "github.com/signalapp/keytransparency/tree/transparency/pb"
	transparency_test "github.com/signalapp/keytransparency/tree/transparency/test"
)

func TestRemoveConsistencyProofsForStatelessVerification_AllowsStatelessSearchVerification(t *testing.T) {
	tree, persistentStore, config, _ := transparency_test.NewTree(t, transparency.ContactMonitoring)

	keys, err := transparency_test.RandomTree(tree, persistentStore, 10, []int{4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.BatchUpdateFake(3); err != nil {
		t.Fatal(err)
	}

	last := transparency_test.Last(persistentStore).Last
	req := &tpb.TreeSearchRequest{
		SearchKey: keys[0],
		Consistency: &tpb.Consistency{
			Last:          last,
			Distinguished: last,
		},
	}
	res, err := tree.Search(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TreeHead.Last) == 0 {
		t.Fatal("Expected last consistency proof")
	}
	if len(res.TreeHead.Distinguished) == 0 {
		t.Fatal("Expected distinguished consistency proof")
	}

	statelessStore := &clientStorage{config: config.Public()}
	if err := transparency.VerifySearch(statelessStore, req, res); err == nil {
		t.Fatal("Expected stateless verification to reject returned consistency proofs")
	} else if !strings.Contains(err.Error(), "consistency proof provided when not expected") {
		t.Fatalf("Expected unexpected consistency proof error, got %v", err)
	}

	removeConsistencyProofsForStatelessVerification(res.TreeHead)

	if res.TreeHead.Last != nil {
		t.Fatal("Expected last consistency proof to be removed")
	}
	if res.TreeHead.Distinguished != nil {
		t.Fatal("Expected distinguished consistency proof to be removed")
	}

	statelessStore = &clientStorage{config: config.Public()}
	if err := transparency.VerifySearch(statelessStore, req, res); err != nil {
		t.Fatalf("Expected stateless verification to pass after removing consistency proofs, got %v", err)
	}
}

func TestRemoveConsistencyProofsForStatelessVerification_NilTreeHead(t *testing.T) {
	removeConsistencyProofsForStatelessVerification(nil)
}
