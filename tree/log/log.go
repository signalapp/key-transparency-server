//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

// Package log implements a log-based Merkle tree where new data is added
// as the right-most leaf.
package log

import (
	"crypto/sha256"
	"fmt"

	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/log/math"
	"github.com/signalapp/keytransparency/tree/sharedmath"
)

// treeHash returns the intermediate hash of left and right.
func treeHash(left, right *nodeData) []byte {
	if err := left.validate(); err != nil {
		panic(err)
	} else if err := right.validate(); err != nil {
		panic(err)
	}

	input := append(left.marshal(), right.marshal()...)
	output := sha256.Sum256(input)
	return output[:]
}

// Tree is an implementation of a log-based Merkle tree where all new data is
// added as the right-most leaf.
type Tree struct {
	tx db.LogStore
}

func NewTree(tx db.LogStore) *Tree {
	return &Tree{tx: tx}
}

// fetch loads the chunks for the requested nodes from the database. It returns
// an error if not all chunks are found.
func (t *Tree) fetchChunkSets(numLeaves uint64, nodes []uint64) (*chunkSet, error) {
	dedup := make(map[uint64]struct{})
	for _, id := range nodes {
		dedup[math.Chunk(id)] = struct{}{}
	}
	chunkIds := make([]uint64, 0, len(dedup))
	for id := range dedup {
		chunkIds = append(chunkIds, id)
	}

	data, err := t.tx.BatchGet(chunkIds)
	if err != nil {
		return nil, err
	}
	for _, id := range chunkIds {
		if _, ok := data[id]; !ok {
			return nil, fmt.Errorf("chunkId %d not found in database", id)
		}
	}

	// Parse chunk set.
	set, err := newChunkSet(numLeaves, data)
	if err != nil {
		return nil, err
	}
	return set, nil
}

// fetchSpecific returns the values for the requested nodes, accounting for the
// ragged right-edge of the tree.
func (t *Tree) fetchSpecific(numLeaves uint64, nodes []uint64) ([][]byte, error) {
	lookup := make([]uint64, 0)

	// Add the nodes that we need to compute the requested hashes.
	rightEdge := make(map[uint64][]uint64)
	for _, id := range nodes {
		if math.IsFullSubtree(id, numLeaves) {
			lookup = append(lookup, id)
		} else {
			subtrees := math.FullSubtrees(id, numLeaves)
			rightEdge[id] = subtrees
			lookup = append(lookup, subtrees...)
		}
	}

	// Load everything from the database in one roundtrip.
	set, err := t.fetchChunkSets(numLeaves, lookup)
	if err != nil {
		return nil, err
	}

	// Extract the data we want to return.
	out := make([][]byte, len(nodes))
	for i, id := range nodes {
		if subtrees, ok := rightEdge[id]; ok {
			out[i] = t.computeRootFromSet(subtrees, set)
		} else {
			out[i] = set.get(id).value
		}
	}

	return out, nil
}

// Get returns the value for the given `entry`, along with its proof of inclusion.
func (t *Tree) Get(entry, treeSize uint64) ([]byte, [][]byte, error) {
	if treeSize == 0 {
		return nil, nil, fmt.Errorf("empty tree")
	} else if entry >= treeSize {
		return nil, nil, fmt.Errorf("can not get leaf beyond right edge of tree: %d >= %d", entry, treeSize)
	}

	leaf := 2 * entry
	copath := math.Copath(leaf, treeSize)
	data, err := t.fetchSpecific(treeSize, append([]uint64{leaf}, copath...))
	if err != nil {
		return nil, nil, fmt.Errorf("fetching: %w", err)
	}

	return data[0], data[1:], nil
}

// GetBatchProof returns a batch proof for the given set of log entries.
func (t *Tree) GetBatchProof(entries []uint64, treeSize uint64) ([][]byte, error) {
	if treeSize == 0 {
		return nil, fmt.Errorf("empty tree")
	} else if len(entries) == 0 {
		return nil, nil
	}
	for _, x := range entries {
		if x >= treeSize {
			return nil, fmt.Errorf("can not get leaf beyond right edge of tree")
		}
	}
	return t.fetchSpecific(treeSize, math.BatchCopath(entries, treeSize))
}

// GetConsistencyProof returns a proof that the current log with n elements is
// an extension of a previous log root with m elements, 0 < m < n.
func (t *Tree) GetConsistencyProof(m, n uint64) ([][]byte, error) {
	if m == 0 {
		return nil, fmt.Errorf("sub-tree for consistency proof must not be empty")
	} else if m >= n {
		return nil, fmt.Errorf("second parameter must be greater than first")
	}
	return t.fetchSpecific(n, math.ConsistencyProof(m, n))
}

// GetRoot gets the root value of the log with the given number of entries
func (t *Tree) GetRoot(treeSize uint64) ([]byte, error) {
	return t.computeRoot(treeSize, nil)
}

// computeRoot computes the root value from a given chunk set.
func (t *Tree) computeRoot(treeSize uint64, set *chunkSet) ([]byte, error) {
	subtrees := math.FullSubtrees(math.Root(treeSize), treeSize)
	if set == nil {
		var err error
		set, err = t.fetchChunkSets(treeSize, subtrees)
		if err != nil {
			return nil, fmt.Errorf("fetching: %w", err)
		}
	}

	return t.computeRootFromSet(subtrees, set), nil
}

// computeRootFromSet computes the root value from a list of subtree node IDs and chunk set
func (t *Tree) computeRootFromSet(subtrees []uint64, set *chunkSet) []byte {
	nd := set.get(subtrees[len(subtrees)-1])
	for i := len(subtrees) - 2; i >= 0; i-- {
		nd = &nodeData{
			leaf:  false,
			value: treeHash(set.get(subtrees[i]), nd),
		}
	}
	return nd.value
}

// Append adds a new element to the end of the log and returns the new root
// value. treeSize is the current size; after this operation is complete, methods to
// this object should be called with treeSize+1.
func (t *Tree) Append(treeSize uint64, value []byte) ([]byte, error) {
	return t.BatchAppend(treeSize, [][]byte{value})
}

// BatchAppend adds several new elements to the end of the log and returns the
// new root value. The treeSize parameter is the current size; after this operation is complete,
// methods on this object should be called with treeSize+len(values).
func (t *Tree) BatchAppend(treeSize uint64, values [][]byte) ([]byte, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("no values to append provided")
	}
	for _, value := range values {
		if len(value) != 32 {
			return nil, fmt.Errorf("value has wrong length: %v", len(value))
		}
	}

	// Calculate the set of nodes that we'll need to update / create.
	newTreeSize := treeSize + uint64(len(values))
	touched := make([]uint64, 0, len(values)*2) // Node ids that are full subtrees after appending the batch, and may need to have their value stored.
	for i := range values {
		leaf := 2 * (treeSize + uint64(i))
		touched = append(touched, leaf)
		for _, id := range math.DirectPath(leaf, newTreeSize) {
			if math.IsFullSubtree(id, newTreeSize) {
				touched = append(touched, id)
			}
		}
	}

	var toFetch []uint64 // These are dedup'ed by fetch.
	createChunks := map[uint64]struct{}{}
	for _, id := range touched {
		chunkId := math.Chunk(id)
		if _, ok := createChunks[chunkId]; ok {
			continue
		}

		// a chunk has a height of 4, so go left three times
		leftmost := sharedmath.Left(sharedmath.Left(sharedmath.Left(chunkId)))
		if id == leftmost {
			// Because this is a left-balanced tree, if we touched the leftmost node in a chunk, the chunk is new
			createChunks[chunkId] = struct{}{}
		} else {
			toFetch = append(toFetch, chunkId)
		}
	}

	// Fetch the chunks we'll need to update along with nodes we'll need to know to compute the new root or updated
	// intermediates. We only need to fetch the copath for the first new node, 2*treeSize, because it provides the
	// values we need for each subsequent update of the intermediate nodes when appending the remaining entries from
	// the batch.
	for _, id := range math.Copath(2*treeSize, treeSize+1) {
		if math.IsFullSubtree(id, treeSize+1) {
			toFetch = append(toFetch, id)
		}
	}
	set, err := t.fetchChunkSets(newTreeSize, toFetch)
	if err != nil {
		return nil, err
	}

	// Add any new chunks to the set and set the correct hashes everywhere.
	for chunkId := range createChunks {
		set.add(chunkId)
	}

	for i, value := range values {
		set.set(2*(treeSize+uint64(i)), value)
	}
	for _, nodeId := range touched {
		if sharedmath.IsLeaf(nodeId) {
			continue
		} else if sharedmath.Level(nodeId)%4 == 0 {
			l, r := sharedmath.Left(nodeId), math.Right(nodeId, newTreeSize)
			intermediate := treeHash(set.get(l), set.get(r))
			set.set(nodeId, intermediate)
		}
	}

	// Push to database.
	t.tx.BatchPut(set.marshalChanges())

	// Compute the new root from the set we've already got.
	return t.computeRoot(newTreeSize, set)
}
