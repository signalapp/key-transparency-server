//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package test

import (
	"bytes"
	"errors"
	mrand "math/rand"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/transparency"
	"github.com/signalapp/keytransparency/tree/transparency/math"
	"github.com/signalapp/keytransparency/tree/transparency/pb"
)

const (
	testValuePrefix = 't'
)

var (
	tombstoneValue = append([]byte{0}, []byte("tombstone")...)
)

func TestTreeWithAuditorHeads(t *testing.T) {
	tree, store, privateConfig, auditorPrivateKeys := NewTree(t, transparency.ThirdPartyAuditing)

	// Add a key to the new tree
	key1, value1 := random(), random()
	updateReq1 := &pb.UpdateRequest{
		SearchKey:   key1,
		Value:       value1,
		Consistency: Last(store),
	}

	// Don't verify this update because we haven't set an auditor tree head yet
	_, err := tree.UpdateSimple(updateReq1)
	if err != nil {
		t.Fatal(err)
	}

	// Set auditor 1's tree head
	root, err := tree.GetLogTree().GetRoot(1)
	if err != nil {
		t.Fatal(err)
	}
	auditor1Head, _, err := transparency.SignNewAuditorHead(auditorPrivateKeys[0], privateConfig.Public(), 1, root, exampleAuditorName1)
	if err != nil {
		t.Fatal(err)
	}
	err = tree.SetAuditorHead(&pb.AuditorTreeHead{
		TreeSize:  auditor1Head.TreeSize,
		Timestamp: auditor1Head.Timestamp,
		Signature: auditor1Head.Signature,
	}, exampleAuditorName1)
	if err != nil {
		t.Fatal(err)
	}

	// Add another key to the tree
	key2, value2 := random(), random()
	updateReq2 := &pb.UpdateRequest{
		SearchKey:   key2,
		Value:       value2,
		Consistency: Last(store),
	}
	updateRes2, err := tree.UpdateSimple(updateReq2)
	if err != nil {
		t.Fatal(err)
	} else if err := transparency.VerifyUpdate(store, updateReq2, updateRes2); err != nil {
		t.Fatal(err)
	}

	// Set auditor 2's tree head
	root, err = tree.GetLogTree().GetRoot(2)
	if err != nil {
		t.Fatal(err)
	}
	auditor2Head, _, err := transparency.SignNewAuditorHead(auditorPrivateKeys[1], privateConfig.Public(), 2, root, exampleAuditorName2)
	if err != nil {
		t.Fatal(err)
	}
	err = tree.SetAuditorHead(&pb.AuditorTreeHead{
		TreeSize:  auditor2Head.TreeSize,
		Timestamp: auditor2Head.Timestamp,
		Signature: auditor2Head.Signature,
	}, exampleAuditorName2)
	if err != nil {
		t.Fatal(err)
	}

	// Search for the first key stored; both auditor tree heads should be verified
	searchReq := &pb.TreeSearchRequest{
		SearchKey:   key1,
		Consistency: Last(store),
	}
	searchRes, err := tree.Search(searchReq)
	if err != nil {
		t.Fatal(err)
	} else if err := transparency.VerifySearch(store, searchReq, searchRes); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(searchRes.Value.Value, value1) {
		t.Fatal("unexpected value returned")
	}
}

func TestTree_SetAuditorHead_FirstCommitFails(t *testing.T) {
	tree, store, privateConfig, auditorPrivateKeys := NewTreeWithStore(t,
		transparency.ThirdPartyAuditing,
		// We want the commit to fail after 1 update
		newCommitFailStore(db.NewMemoryTransparencyStore(), 1))

	// Add a key to the new tree
	key, value := random(), random()
	updateReq := &pb.UpdateRequest{
		SearchKey:   key,
		Value:       value,
		Consistency: Last(store),
	}

	_, err := tree.UpdateSimple(updateReq)
	if err != nil {
		t.Fatal(err)
	}

	// Set auditor's first tree head
	root, err := tree.GetLogTree().GetRoot(1)
	if err != nil {
		t.Fatal(err)
	}
	auditorHead, _, err := transparency.SignNewAuditorHead(auditorPrivateKeys[0], privateConfig.Public(), 1, root, exampleAuditorName1)
	if err != nil {
		t.Fatal(err)
	}
	err = tree.SetAuditorHead(&pb.AuditorTreeHead{
		TreeSize:  auditorHead.TreeSize,
		Timestamp: auditorHead.Timestamp,
		Signature: auditorHead.Signature,
	}, exampleAuditorName1)
	if err == nil {
		t.Fatal(err)
	}

	// Search for the first key and check that no auditor tree head exists
	searchReq := &pb.TreeSearchRequest{
		SearchKey:   key,
		Consistency: Last(store),
	}
	searchRes, err := tree.Search(searchReq)
	if err != nil {
		t.Fatal(err)
	}

	if len(searchRes.GetTreeHead().GetFullAuditorTreeHeads()) > 0 {
		t.Fatal("expected no auditor tree heads")
	}
}

func TestTree_SetAuditorHead_SecondCommitFails(t *testing.T) {
	tree, store, privateConfig, auditorPrivateKeys := NewTreeWithStore(t,
		transparency.ThirdPartyAuditing,
		// We want the commit to fail after two updates (1 simple update, 1 set auditor head)
		newCommitFailStore(db.NewMemoryTransparencyStore(), 2))

	// Add a key to the new tree
	key1, value1 := random(), random()
	updateReq1 := &pb.UpdateRequest{
		SearchKey:   key1,
		Value:       value1,
		Consistency: Last(store),
	}

	_, err := tree.UpdateSimple(updateReq1)
	if err != nil {
		t.Fatal(err)
	}

	// Set auditor's first tree head
	root, err := tree.GetLogTree().GetRoot(1)
	if err != nil {
		t.Fatal(err)
	}
	auditorHead1, _, err := transparency.SignNewAuditorHead(auditorPrivateKeys[0], privateConfig.Public(), 1, root, exampleAuditorName1)
	if err != nil {
		t.Fatal(err)
	}
	err = tree.SetAuditorHead(&pb.AuditorTreeHead{
		TreeSize:  auditorHead1.TreeSize,
		Timestamp: auditorHead1.Timestamp,
		Signature: auditorHead1.Signature,
	}, exampleAuditorName1)
	if err != nil {
		t.Fatal(err)
	}

	// Set auditor's second tree head. It contains a unix timestamp in milliseconds
	// so the signature will be different from the first one if we sleep for a millisecond.
	time.Sleep(1 * time.Millisecond)
	root, err = tree.GetLogTree().GetRoot(1)
	if err != nil {
		t.Fatal(err)
	}
	auditorHead2, _, err := transparency.SignNewAuditorHead(auditorPrivateKeys[0], privateConfig.Public(), 1, root, exampleAuditorName1)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(auditorHead1.Signature, auditorHead2.Signature) {
		t.Fatal("expected auditor heads to be different")
	}

	err = tree.SetAuditorHead(&pb.AuditorTreeHead{
		TreeSize:  auditorHead2.TreeSize,
		Timestamp: auditorHead2.Timestamp,
		Signature: auditorHead2.Signature,
	}, exampleAuditorName1)
	if err == nil {
		t.Fatal(err)
	}

	// Search for the first key and check that the stored auditor tree head is the first one
	searchReq := &pb.TreeSearchRequest{
		SearchKey:   key1,
		Consistency: Last(store),
	}
	searchRes, err := tree.Search(searchReq)
	if err != nil {
		t.Fatal(err)
	}

	auditorTreeSize := searchRes.GetTreeHead().GetFullAuditorTreeHeads()[0].GetTreeHead().GetTreeSize()
	signature := searchRes.GetTreeHead().GetFullAuditorTreeHeads()[0].GetTreeHead().GetSignature()
	if auditorTreeSize != 1 || !bytes.Equal(signature, auditorHead1.Signature) {
		t.Fatal("wrong auditor head")
	}
}

func TestTree(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	var (
		keys   [][]byte
		values [][]byte
	)

	for i := 0; i < 100; i++ {
		dice := mrand.Intn(4)

		if dice == 0 && len(keys) > 0 { // Search for an existing key.
			i := mrand.Intn(len(keys))
			req := &pb.TreeSearchRequest{
				SearchKey:   keys[i],
				Consistency: Last(store),
			}
			res, err := tree.Search(req)
			if err != nil {
				t.Fatal(err)
			} else if err := transparency.VerifySearch(store, req, res); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(res.Value.Value, values[i]) {
				t.Fatal("unexpected value returned")
			}
		} else if dice == 1 { // Add a new key.
			key, value := random(), random()
			req := &pb.UpdateRequest{
				SearchKey:   key,
				Value:       value,
				Consistency: Last(store),
			}
			res, err := tree.UpdateSimple(req)
			if err != nil {
				t.Fatal(err)
			} else if err := transparency.VerifyUpdate(store, req, res); err != nil {
				t.Fatal(err)
			}
			keys, values = append(keys, key), append(values, value)
		} else if dice == 2 && len(keys) > 0 { // Update an existing key.
			i, value := mrand.Intn(len(keys)), random()
			req := &pb.UpdateRequest{
				SearchKey:   keys[i],
				Value:       value,
				Consistency: Last(store),
			}
			res, err := tree.UpdateSimple(req)
			if err != nil {
				t.Fatal(err)
			} else if err := transparency.VerifyUpdate(store, req, res); err != nil {
				t.Fatal(err)
			}
			values[i] = value
		} else if dice == 3 && len(keys) > 0 { // Add some fake updates.
			if err := tree.BatchUpdateFake(5); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSearch_EmptyTree_ProofGeneration(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Populate tree with some random data.
	temp, err := RandomTree(tree, store, 100, []int{10, 50, 75}, []int{})

	emptyTreeSize := uint64(0)
	req := &pb.TreeSearchRequest{
		SearchKey:   temp[0],
		Consistency: &pb.Consistency{Last: &emptyTreeSize},
	}

	_, err = tree.Search(req)

	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.InvalidArgument {
		t.Fatal("Expected `invalid argument` error, got ", err)
	}

	req.Consistency = &pb.Consistency{Distinguished: &emptyTreeSize}
	_, err = tree.Search(req)
	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.InvalidArgument {
		t.Fatal("Expected `invalid argument` error, got ", err)
	}

	req.Consistency = &pb.Consistency{Last: &emptyTreeSize, Distinguished: &emptyTreeSize}
	_, err = tree.Search(req)
	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.InvalidArgument {
		t.Fatal("Expected `invalid argument` error, got ", err)
	}
}

func TestMonitor(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Populate tree with some random data.
	temp, err := RandomTree(tree, store, 100, []int{10, 50, 75}, []int{})
	if err != nil {
		t.Fatal(err)
	}
	key1, key2, key3 := temp[0], temp[1], temp[2]

	// Get the monitoring data for each key and check that it's as expected.
	data1, err := store.GetData(key1)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data1.Ptrs[10]; len(data1.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}
	data2, err := store.GetData(key2)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data2.Ptrs[50]; len(data2.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}
	data3, err := store.GetData(key3)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data3.Ptrs[75]; len(data3.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}

	// Submit a Monitor request and check that the response verifies.
	req := &pb.MonitorRequest{
		Keys: []*pb.MonitorKey{
			{SearchKey: key1, EntryPosition: data1.Entries()[0], CommitmentIndex: data1.Index},
			{SearchKey: key2, EntryPosition: data2.Entries()[0], CommitmentIndex: data2.Index},
			{SearchKey: key3, EntryPosition: data3.Entries()[0], CommitmentIndex: data3.Index},
		},
		Consistency: Last(store),
	}
	res, err := tree.Monitor(req)
	if err != nil {
		t.Fatal(err)
	} else if err := transparency.VerifyMonitor(store, req, res); err != nil {
		t.Fatal(err)
	}

	// Check that monitoring data was successfully updated.
	data1, err = store.GetData(key1)
	if err != nil {
		t.Fatal(err)
	} else if len(data1.Ptrs) != 1 || data1.Ptrs[63] != 0 {
		t.Fatal("monitoring data not as expected")
	}
	data2, err = store.GetData(key2)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data2.Ptrs[63]; len(data2.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}
	data3, err = store.GetData(key3)
	if err != nil {
		t.Fatal(err)
	} else if v, ok := data3.Ptrs[95]; len(data3.Ptrs) != 1 || !ok || v != 0 {
		t.Fatal("monitoring data not as expected")
	}

	// Check that a 0 value for last or distinguished tree size returns an error
	emptyTreeSize := uint64(0)
	req.Consistency = &pb.Consistency{Last: &emptyTreeSize}
	_, err = tree.Monitor(req)
	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.InvalidArgument {
		t.Fatal("Expected `invalid argument` error, got ", err)
	}

	req.Consistency = &pb.Consistency{Distinguished: &emptyTreeSize}
	_, err = tree.Monitor(req)
	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.InvalidArgument {
		t.Fatal("Expected `invalid argument` error, got ", err)
	}

	req.Consistency = &pb.Consistency{Last: &emptyTreeSize, Distinguished: &emptyTreeSize}
	_, err = tree.Monitor(req)
	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.InvalidArgument {
		t.Fatal("Expected `invalid argument` error, got ", err)
	}
}

func TestMonitorOnlyAllowsRightEntries(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Populate tree with some random data.
	temp, err := RandomTree(tree, store, 100, []int{10}, []int{50, 75})
	if err != nil {
		t.Fatal(err)
	}
	key := temp[0]

	// Compute the set of allowed entries.
	all := append([]uint64{10, 50, 75},
		append(math.MonitoringPath(10, 10, 100),
			append(math.MonitoringPath(50, 10, 100),
				math.MonitoringPath(75, 10, 100)...)...)...)
	allowed := make(map[uint64]struct{})
	for _, x := range all {
		allowed[x] = struct{}{}
	}

	// Go through each entry in the log, and send a monitor request for that
	// entry. Check that the only requests that succeed are the ones in
	// whitelisted entries.
	for x := uint64(0); x < 100; x++ {
		data, err := store.GetData(key)
		if err != nil {
			t.Fatal(err)
		}
		req := &pb.MonitorRequest{
			Keys:        []*pb.MonitorKey{{SearchKey: key, EntryPosition: x, CommitmentIndex: data.Index}},
			Consistency: Last(store),
		}
		_, err = tree.Monitor(req)
		if _, ok := allowed[x]; ok { // Expect to succeed.
			if err != nil {
				t.Fatal(err)
			}
		} else { // Expect to fail.
			if err == nil {
				t.Fatal("request succeeded when failure was expected")
			}
		}
	}
}

func TestMonitorCommitmentIndexValidation(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Populate tree with some random data.
	temp, err := RandomTree(tree, store, 100, []int{10}, []int{50, 75})
	if err != nil {
		t.Fatal(err)
	}
	key := temp[0]

	// Get the monitoring data for each key and check that it's as expected.
	data, err := store.GetData(key)
	if err != nil {
		t.Fatal(err)
	}
	// Submit a Monitor request with an invalid (incorrect length) commitment index
	reqInvalidIndex := &pb.MonitorRequest{
		Keys: []*pb.MonitorKey{
			{SearchKey: key, EntryPosition: data.Entries()[0], CommitmentIndex: []byte{}},
		},
		Consistency: Last(store),
	}

	_, err = tree.Monitor(reqInvalidIndex)
	if err == nil {
		t.Fatal("request succeeded with invalid commitment index")
	}

	// Submit a Monitor request with a mismatched commitment index
	index := make([]byte, 32)
	copy(index, data.Index)
	index[0] = index[0] + 1
	reqMismatchedIndex := &pb.MonitorRequest{
		Keys: []*pb.MonitorKey{
			{SearchKey: key, EntryPosition: data.Entries()[0], CommitmentIndex: index},
		},
		Consistency: Last(store),
	}

	_, err = tree.Monitor(reqMismatchedIndex)
	if err == nil {
		t.Fatal("request succeeded with mismatched commitment index")
	}
}

func TestTombstoneUpdate_IndexExists_ExpectedValueMatches(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Insert a search key
	searchKey := append([]byte{shared.AciPrefix}, []byte("searchKey")...)
	originalValue := append([]byte{testValuePrefix}, []byte("value1")...)

	preUpdate, err := tree.PreUpdate(&pb.UpdateRequest{
		SearchKey:   searchKey,
		Value:       originalValue,
		Consistency: &pb.Consistency{},
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = tree.BatchUpdate([]*transparency.PreUpdateState{preUpdate})

	if err != nil {
		t.Fatal(err)
	}

	// Update the search key with the tombstone value
	preUpdate, err = tree.PreUpdate(&pb.UpdateRequest{
		SearchKey:              searchKey,
		Value:                  tombstoneValue,
		Consistency:            &pb.Consistency{},
		ExpectedPreUpdateValue: originalValue,
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = tree.UpdateExistingIndexWithTombstoneValue(preUpdate)

	if err != nil {
		t.Fatal(err)
	}

	req := &pb.TreeSearchRequest{
		SearchKey:   searchKey,
		Consistency: Last(store),
	}
	res, err := tree.Search(req)
	if err != nil {
		t.Fatal(err)
	}

	// Search key should now map to tombstone value
	if !bytes.Equal(res.Value.Value, tombstoneValue) {
		t.Fatal("unexpected mapped value")
	}
}

func TestTombstoneUpdate_IndexExists_ExpectedValueDoesNotMatch(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Insert a search key
	searchKey := append([]byte{shared.AciPrefix}, []byte("searchKey")...)
	originalValue := append([]byte{testValuePrefix}, []byte("value1")...)

	preUpdate, err := tree.PreUpdate(&pb.UpdateRequest{
		SearchKey:   searchKey,
		Value:       originalValue,
		Consistency: &pb.Consistency{},
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = tree.BatchUpdate([]*transparency.PreUpdateState{preUpdate})

	if err != nil {
		t.Fatal(err)
	}

	// Pass in a different expected pre-update value from what exists in the tree
	differentValue := append([]byte{testValuePrefix}, []byte("value2")...)
	preUpdate, err = tree.PreUpdate(&pb.UpdateRequest{
		SearchKey:              searchKey,
		Value:                  tombstoneValue,
		Consistency:            &pb.Consistency{},
		ExpectedPreUpdateValue: differentValue,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Expected pre-update value does not match what's in the tree; abort update
	// and check that the search key still maps to original value
	_, err = tree.UpdateExistingIndexWithTombstoneValue(preUpdate)

	if !errors.Is(err, transparency.ErrTombstoneUnexpectedPreUpdateValue) {
		t.Fatalf("Expected error %v", transparency.ErrTombstoneUnexpectedPreUpdateValue)
	}

	// Search key should still map to original value
	req := &pb.TreeSearchRequest{
		SearchKey:   searchKey,
		Consistency: Last(store),
	}
	res, err := tree.Search(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.Value.Value, originalValue) {
		t.Fatal("unexpected mapped value")
	}
}

func TestTombstoneUpdate_IndexNotFound(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Insert a search key
	searchKey := append([]byte{shared.AciPrefix}, []byte("searchKey")...)
	originalValue := append([]byte{testValuePrefix}, []byte("value1")...)

	preUpdate, err := tree.PreUpdate(&pb.UpdateRequest{
		SearchKey:   searchKey,
		Value:       originalValue,
		Consistency: &pb.Consistency{},
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = tree.BatchUpdate([]*transparency.PreUpdateState{preUpdate})

	if err != nil {
		t.Fatal(err)
	}

	// Update a different search key with the tombstone value
	differentSearchKey := append([]byte{shared.AciPrefix}, []byte("differentSearchKey")...)
	preUpdate, err = tree.PreUpdate(&pb.UpdateRequest{
		SearchKey:              differentSearchKey,
		Value:                  tombstoneValue,
		Consistency:            &pb.Consistency{},
		ExpectedPreUpdateValue: originalValue,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Index should not be found; abort update
	_, err = tree.UpdateExistingIndexWithTombstoneValue(preUpdate)

	if !errors.Is(err, transparency.ErrTombstoneIndexNotFound) {
		t.Fatalf("Expected error %v", transparency.ErrTombstoneIndexNotFound)
	}

	// That different search key should still not be found
	req := &pb.TreeSearchRequest{
		SearchKey:   differentSearchKey,
		Consistency: Last(store),
	}

	_, err = tree.Search(req)
	if gprcError, ok := status.FromError(err); !ok || gprcError.Code() != codes.NotFound {
		t.Fatal("Expected `not found` error, got ", err)
	}
}

func TestMultipleUpdatesToSameKeyInBatch(t *testing.T) {
	tree, store, _, _ := NewTree(t, transparency.ContactMonitoring)

	searchKey := []byte("searchKey")

	values := []string{"value1", "value2", "value3", "value4", "value5"}
	states := make([]*transparency.PreUpdateState, len(values))

	for i, v := range values {
		preUpdate, err := tree.PreUpdate(&pb.UpdateRequest{
			SearchKey:   searchKey,
			Value:       []byte(v),
			Consistency: &pb.Consistency{},
		})
		if err != nil {
			t.Fatal(err)
		}

		states[i] = preUpdate
	}

	_, err := tree.BatchUpdate(states)
	if err != nil {
		t.Fatal(err)
	}

	req := &pb.TreeSearchRequest{
		SearchKey:   searchKey,
		Consistency: Last(store),
	}
	res, err := tree.Search(req)
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(res.Value.Value, []byte(values[len(values)-1])) {
		t.Fatal("unexpected mapped value")
	}

	maxCtr := uint32(0)
	for _, step := range res.Search.Steps {
		if ctr := step.Prefix.Counter; ctr > maxCtr {
			maxCtr = ctr
		}
	}
	if maxCtr != uint32(len(values)-1) {
		t.Fatal("unexpected search key ctr")
	}
}

func TestUpdateRejectsDuplicates(t *testing.T) {
	tree, _, _, _ := NewTree(t, transparency.ContactMonitoring)

	// Utility function to generate a list of PreUpdateStates changing a fixed
	// search key to a given value.
	makeStates := func(vals [][]byte) []*transparency.PreUpdateState {
		states := make([]*transparency.PreUpdateState, len(vals))

		for i, val := range vals {
			preUpdate, err := tree.PreUpdate(&pb.UpdateRequest{
				SearchKey:   []byte("searchKey"),
				Value:       val,
				Consistency: &pb.Consistency{},
			})
			if err != nil {
				t.Fatal(err)
			}
			states[i] = preUpdate
		}

		return states
	}
	// Utility function to check whether each PostUpdateState in a list was
	// rejected for being a duplicate update or not.
	checkResults := func(results []*transparency.PostUpdateState, dup []bool) {
		if len(results) != len(dup) {
			t.Fatal("unexpected number of responses received")
		}
		for i, res := range results {
			_, err := tree.PostUpdate(res)
			if dup[i] && err != transparency.ErrDuplicateUpdate {
				t.Fatalf("unexpected error: %v", err)
			} else if !dup[i] && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	}

	// Test case 1: no duplicates.
	states := makeStates([][]byte{[]byte("value1"), []byte("value2"), []byte("value3")})
	results, err := tree.BatchUpdate(states)
	if err != nil {
		t.Fatal(err)
	}
	checkResults(results, []bool{false, false, false})

	// Test case 2: duplicate within set of requests.
	states = makeStates([][]byte{[]byte("value4"), []byte("value4"), []byte("value5")})
	results, err = tree.BatchUpdate(states)
	if err != nil {
		t.Fatal(err)
	}
	checkResults(results, []bool{false, true, false})

	// Test case 3: duplicate with initial value.
	states = makeStates([][]byte{[]byte("value5"), []byte("value6")})
	results, err = tree.BatchUpdate(states)
	if err != nil {
		t.Fatal(err)
	}
	checkResults(results, []bool{true, false})

	// Test case 4: duplicate with initial value but incorrect cache is provided.
	states = makeStates([][]byte{[]byte("value7"), []byte("value8")})

	other := makeStates([][]byte{[]byte("value7")})
	results, err = tree.BatchUpdate(other)
	if err != nil {
		t.Fatal(err)
	}
	checkResults(results, []bool{false})

	results, err = tree.BatchUpdate(states)
	if err != nil {
		t.Fatal(err)
	}
	checkResults(results, []bool{true, false})

	// Test case 5: value flip-flops are ok
	states = makeStates([][]byte{[]byte("value9"), []byte("value10"), []byte("value9")})
	results, err = tree.BatchUpdate(states)
	if err != nil {
		t.Fatal(err)
	}
	checkResults(results, []bool{false, false, false})
}

func BenchmarkUpdate1(b *testing.B) {
	tree, store, _, _ := NewTree(b, transparency.ContactMonitoring)
	_, err := RandomTree(tree, store, 100, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	preStates := make([]*transparency.PreUpdateState, b.N)
	for i := 0; i < b.N; i++ {
		state, err := tree.PreUpdate(&pb.UpdateRequest{
			SearchKey: random(), Value: random(),
		})
		if err != nil {
			b.Fatal(err)
		}
		tree.GetCacheControl().StopTracking()
		preStates[i] = state
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tree.BatchUpdate([]*transparency.PreUpdateState{preStates[i]}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUpdate10(b *testing.B) {
	const batchSize = 10

	tree, store, _, _ := NewTree(b, transparency.ContactMonitoring)
	_, err := RandomTree(tree, store, 100, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	preStates := make([][]*transparency.PreUpdateState, b.N)
	for i := 0; i < b.N; i++ {
		for j := 0; j < batchSize; j++ {
			state, err := tree.PreUpdate(&pb.UpdateRequest{
				SearchKey: random(), Value: random(),
			})
			if err != nil {
				b.Fatal(err)
			}
			tree.GetCacheControl().StopTracking()
			preStates[i] = append(preStates[i], state)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tree.BatchUpdate(preStates[i]); err != nil {
			b.Fatal(err)
		}
	}
}
