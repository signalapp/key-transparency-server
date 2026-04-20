//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package test

import (
	"testing"

	"github.com/signalapp/keytransparency/tree/transparency"
	"github.com/signalapp/keytransparency/tree/transparency/pb"
)

func TestVerifySearch(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Populate tree with some random data.
	temp, err := RandomTree(tree, store, 10, []int{4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := temp[0]

	// Produce a valid search result for key.
	req := &pb.TreeSearchRequest{SearchKey: key, Consistency: Last(store)}
	res, err := tree.Search(req)
	if err != nil {
		t.Fatal(err)
	}

	// Check that changing any part of the proof causes verification to fail.
	res.TreeHead.TreeHead.TreeSize += 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.TreeHead.TreeHead.TreeSize -= 1

	res.TreeHead.TreeHead.Timestamp += 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.TreeHead.TreeHead.Timestamp -= 1

	res.TreeHead.TreeHead.Signatures[0].Signature[0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.TreeHead.TreeHead.Signatures[0].Signature[0] ^= 1

	consistency := res.TreeHead.Last
	res.TreeHead.Last = [][]byte{random()}
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.TreeHead.Last = consistency

	res.VrfProof[0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.VrfProof[0] ^= 1

	res.Search.Pos += 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.Search.Pos -= 1

	res.Search.Steps[0].Commitment[0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.Search.Steps[0].Commitment[0] ^= 1

	res.Search.Inclusion[0][0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.Search.Inclusion[0][0] ^= 1

	res.Opening[0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.Opening[0] ^= 1

	res.Value.Value[0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.Value.Value[0] ^= 1

	req.SearchKey[0] ^= 1
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	req.SearchKey[0] ^= 1

	// Check that omitting the service operator's signature(s) errors out
	signatures := res.TreeHead.TreeHead.Signatures
	res.TreeHead.TreeHead.Signatures = nil
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.TreeHead.TreeHead.Signatures = signatures

	res.TreeHead.TreeHead.Signatures = []*pb.Signature{}
	if err := transparency.VerifySearch(store, req, res); err == nil {
		t.Fatal("expected error")
	}
	res.TreeHead.TreeHead.Signatures = signatures

	// Check that unmodified proof verifies.
	if err := transparency.VerifySearch(store, req, res); err != nil {
		t.Fatal(err)
	}
}

// Note: VerifySearch and VerifyUpdate are the same internally, so there's only
// a test for VerifySearch.

func TestSearchUpdatesMonitoringData(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Populate tree with some random data.
	temp, err := RandomTree(tree, store, 10, []int{4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := temp[0]

	// Check that monitoring data is as expected.
	data, err := store.GetData(key)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data.Ptrs[4]; len(data.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}

	// Search for key.
	req := &pb.TreeSearchRequest{SearchKey: key, Consistency: Last(store)}
	res, err := tree.Search(req)
	if err != nil {
		t.Fatal(err)
	} else if err := transparency.VerifySearch(store, req, res); err != nil {
		t.Fatal(err)
	}

	// Check that monitoring data is as expected.
	data, err = store.GetData(key)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data.Ptrs[7]; len(data.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}
}
