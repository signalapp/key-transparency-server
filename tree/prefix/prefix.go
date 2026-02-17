//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//go:generate protoc --go_out=. --go_opt=paths=source_relative pb/prefix.proto

// Package prefix implements a Merkle prefix tree that supports proofs of
// inclusion only.
package prefix

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/prefix/pb"
)

const IndexLength = 32

// SearchResult is the output from executing a search in a specific prefix tree for an index.
//
// There are two use cases for searching the prefix tree:
//  1. ["Indexing"] To find the log entry positions of:
//  1. the first update, and
//  2. the most recent update OR the update corresponding to the desired version.
//     This allows the server to conduct a more efficient binary search in the *log tree* for that log entry position.
//     In this use case, the server will always start out searching the latest log entry and will only use FirstUpdatePosition and LatestUpdatePosition
//     from the search result.
//  2. ["SearchProof generation"] Once the server has the path in the log tree to a given log entry position, it must generate the
//     data necessary to prove that the given log entry position really is the most recent update to the index. To do so,
//     the server will search the prefix tree associated with each log entry in that path, returning the Commitment, inclusion Proof, and Counter
//     data necessary for a verifier to recompute the prefix tree root hash and later, the log tree leaf hash for the entry.
type SearchResult struct {
	// FirstUpdatePosition returns the log entry position of the first occurrence of this index in the given prefix tree.
	FirstUpdatePosition uint64
	// LatestUpdatePosition returns the log entry position of the most recent occurrence of the index in the given prefix tree.
	// Note that the given prefix tree is not necessarily the one associated with latest log entry.
	LatestUpdatePosition uint64

	// Commitment returns the commitment associated with this prefix tree.
	// It may return nil if this prefix tree was created by a fake update.
	Commitment []byte
	// Proof returns a proof of inclusion from the prefix tree leaf where the search terminated to the prefix tree root.
	Proof [][]byte
	// Counter returns how many times the index has been updated in this prefix tree.
	Counter uint32
}

// Tree is the high-level implementation of the Merkle prefix tree, backed by a
// connection to a persistent database.
type Tree struct {
	// aesKey is used to deterministically build the contents
	// of nonexistent sibling nodes while computing Merkle hashes in this tree.
	aesKey []byte
	tx     db.PrefixStore
}

// NewTree returns a new instance of a prefix tree.
func NewTree(aesKey []byte, tx db.PrefixStore) *Tree {
	return &Tree{aesKey: aesKey, tx: tx}
}

// BatchSearch returns an unexecuted search structure.
func (t *Tree) BatchSearch(treeSize uint64, index []byte) (*Search, error) {
	if treeSize == 0 {
		return nil, errors.New("tree is empty")
	} else if len(index) != IndexLength {
		return nil, fmt.Errorf("index length must be %v bytes", IndexLength)
	}
	return &Search{index: index, ptr: treeSize - 1}, nil
}

// BatchExec runs several searches in parallel, minimizing the number of
// database lookups required.
func (t *Tree) BatchExec(searches []*Search) ([]*SearchResult, error) {
	pos, results, err := newSearchBatch(t.aesKey, t.tx, searches).exec(false)
	if err != nil {
		return nil, err
	}
	out := make([]*SearchResult, 0, len(results))
	for i, res := range results {
		entry, ok := res.(*cachedLogEntry)
		if !ok {
			return nil, status.Error(codes.NotFound, "failed to find index")
		}
		out = append(out, &SearchResult{
			Proof:   entry.getCopath(),
			Counter: entry.inner.Leaf.Ctr,

			FirstUpdatePosition:  entry.inner.FirstUpdatePosition,
			LatestUpdatePosition: pos[i],
			Commitment:           entry.inner.Leaf.Commitment,
		})
	}
	return out, nil
}

// SearchForVersion executes a search in the tree of the given size for the index with a counter value
// equal to indexVersion.
// The SearchResult returns the latest update position *in the last tree size that was searched*, which is not necessarily
// the original treeSize.
func (t *Tree) SearchForVersion(treeSize uint64, index []byte, indexVersion uint32) (*SearchResult, error) {
	var res *SearchResult
	nextTreeSizeToSearch := treeSize

	// Search for the index with the requested indexVersion counter by recursively searching in earlier
	// and earlier entries of the log for the most recent update to the given index, until we find the desired index version
	// or we get back a "not found" error.
	var err error
	for {
		res, err = t.Search(nextTreeSizeToSearch, index)
		if err != nil {
			return nil, fmt.Errorf("running versioned search: %w", err)
		}

		if res.Counter != indexVersion {
			// Tree size is one-indexed, but positions are zero-indexed. For example,
			// if index A's latest update position is 8, that means that that update was the 9th entry in the tree.
			// So in the next iteration, we want to search in the tree with 8 entries for the latest update to index A.
			nextTreeSizeToSearch = res.LatestUpdatePosition
		} else {
			break
		}
	}

	return res, nil
}

// Search executes a search for `index` in the requested tree.
func (t *Tree) Search(treeSize uint64, index []byte) (*SearchResult, error) {
	search, err := t.BatchSearch(treeSize, index)
	if err != nil {
		return nil, fmt.Errorf("creating search: %w", err)
	}
	res, err := t.BatchExec([]*Search{search})
	if err != nil {
		return nil, fmt.Errorf("running search: %w", err)
	}
	return res[0], nil
}

// Trace performs the same database lookups in the same order as Search, without
// computing the intermediate hashes to produce a full search result.
//
// Returns the log position that the search for each index ended at. If an index was not found, its value will be math.MaxUint64.
func (t *Tree) Trace(treeSize uint64, indices [][]byte) ([]uint64, error) {
	if treeSize == 0 {
		out := make([]uint64, len(indices))
		for i := range out {
			out[i] = math.MaxUint64
		}
		return out, nil
	}

	searches := make([]*Search, len(indices))
	for i, index := range indices {
		search, err := t.BatchSearch(treeSize, index)
		if err != nil {
			return nil, fmt.Errorf("creating search: %w", err)
		}
		searches[i] = search
	}
	positions, results, err := newSearchBatch(t.aesKey, t.tx, searches).exec(true)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(positions))
	for i, pos := range positions {
		if _, ok := results[i].(*cachedLogEntry); ok {
			out[i] = pos
		} else {
			out[i] = math.MaxUint64
		}
	}
	return out, nil
}

// InsertFake changes the tree like a random new entry was inserted, without
// actually doing so.
//
// The current tree size is given in `treeSize`; after this method returns
// successfully, the tree may be used with `treeSize+1`.
func (t *Tree) InsertFake(treeSize uint64) ([]byte, error) {
	var entry *pb.LogEntry
	if treeSize == 0 {
		// entry = &pb.LogEntry{
		// 	Index:    nil,
		// 	Copath: nil,
		// 	Seed:   treeSize,
		// }
		return nil, fmt.Errorf("can not do fake insert in an empty tree")
	} else {
		index := make([]byte, IndexLength)
		if _, err := rand.Read(index); err != nil {
			return nil, fmt.Errorf("getting randomness: %w", err)
		}
		search, err := t.BatchSearch(treeSize, index)
		if err != nil {
			return nil, fmt.Errorf("creating search: %w", err)
		}
		_, results, err := newSearchBatch(t.aesKey, t.tx, []*Search{search}).exec(false)
		if err != nil {
			return nil, fmt.Errorf("running search: %w", err)
		}
		failed, ok := results[0].(*failedSearch)
		if !ok {
			return nil, fmt.Errorf("unexpected error")
		}
		cutoff := (len(failed.copath) + 7) / 8
		entry = &pb.LogEntry{
			Index:               index[:cutoff],
			Copath:              failed.copath,
			FirstUpdatePosition: treeSize,
		}
	}

	cached := &cachedLogEntry{inner: entry, aesKey: t.aesKey}
	cached.precompute()

	raw, err := proto.Marshal(entry)
	if err != nil {
		return nil, err
	}
	t.tx.Put(treeSize, raw)

	return cached.rollup(0), nil
}

type Entry struct {
	Index, Commitment []byte
}

// sequence is a wrapper around sequencePart, that allows sequencing to happen
// on many cores instead of just one.
func (t *Tree) sequence(treeSize uint64, entries []Entry, fake bool) ([]*cachedLogEntry, error) {
	if len(entries) < 64 { // Skip multi-threaded stuff for small batches.
		return t.sequencePart(treeSize, 0, entries, fake)
	}

	type sequenceResult struct {
		start int
		part  []*cachedLogEntry
		err   error
	}
	ch := make(chan sequenceResult)

	// Determine the number of cores to split sequencing across.
	cpu := runtime.NumCPU()
	if cpu > 8 {
		cpu = 8
	}

	// Spawn a set of goroutines to sequence a subset of entries.
	goroutines := 0
	step := (len(entries) + cpu - 1) / cpu
	for start := 0; start < len(entries); start += step {
		i, j := start, start+step
		if j > len(entries) {
			j = len(entries)
		}
		go func() {
			part, err := t.sequencePart(treeSize, i, entries[i:j], fake)
			ch <- sequenceResult{i, part, err}
		}()
		goroutines++
	}

	// Collect results and return.
	sequenced := make([]*cachedLogEntry, len(entries))
	var err error
	for i := 0; i < goroutines; i++ {
		if res := <-ch; res.err != nil {
			err = res.err
		} else {
			copy(sequenced[res.start:], res.part)
		}
	}
	return sequenced, err
}

// sequencePart takes a subset of new entries to insert into the prefix tree and
// returns a cachedLogEntry for each, corresponding to the log entry that would
// be stored if the tree had treeSize+1 entries.
// fake is whether the provided log entries are fake, which affects the data stored in the cachedLogEntry.
func (t *Tree) sequencePart(treeSize uint64, offset int, entries []Entry, fake bool) ([]*cachedLogEntry, error) {
	var searches []*Search
	for _, entry := range entries {
		search, err := t.BatchSearch(treeSize, entry.Index)
		if err != nil {
			return nil, fmt.Errorf("creating search: %w", err)
		}
		searches = append(searches, search)
	}
	_, results, err := newSearchBatch(t.aesKey, t.tx, searches).exec(false)
	if err != nil {
		return nil, fmt.Errorf("running search: %w", err)
	}

	var sequenced []*cachedLogEntry
	for i, res := range results {
		switch res := res.(type) {
		case *cachedLogEntry:
			res.inner.Leaf.Ctr += 1
			res.inner.Leaf.Commitment = entries[i].Commitment
			res.parents = [256][]byte{} // Should already be empty, but if not.
			sequenced = append(sequenced, res)
		case *failedSearch:
			temp := &cachedLogEntry{
				inner: &pb.LogEntry{
					Copath:              res.copath,
					FirstUpdatePosition: treeSize + uint64(offset+i),
				},
				aesKey: t.aesKey,
			}

			// Fake updates store truncated indexes and no leaf nodes
			if fake {
				cutoff := (len(res.copath) + 7) / 8
				temp.inner.Index = entries[i].Index[:cutoff]
			} else {
				temp.inner.Index = entries[i].Index
				temp.inner.Leaf = &pb.LeafNode{Ctr: 0, Commitment: entries[i].Commitment}
			}

			sequenced = append(sequenced, temp)
		default:
			panic("unreachable")
		}
	}

	// Force precomputation to happen here, while we're in a multi-threaded part
	// of the insert path. Some of this will potentially get thrown away due to
	// changes in final sequencing, but the majority will not.
	for _, entry := range sequenced {
		entry.precompute()
	}

	return sequenced, nil
}

// BatchInsert adds a series of new entries to the tree / increments the counter
// of entries that already exist. It returns the new roots and a search result
// for each entry.
//
// The current treeSize is given in `treeSize`; after this method returns
// successfully, the tree may be used with `treeSize+len(entries)`.
func (t *Tree) BatchInsert(treeSize uint64, entries []Entry, fake bool) ([][]byte, []*SearchResult, error) {
	if len(entries) == 0 {
		return nil, nil, errors.New("no entries to insert provided")
	}
	for _, entry := range entries {
		if len(entry.Index) != IndexLength {
			return nil, nil, fmt.Errorf("index length must be %v bytes", IndexLength)
		} else if len(entry.Commitment) != 32 {
			return nil, nil, errors.New("commitment must be 32 bytes")
		}
	}

	var sequenced []*cachedLogEntry
	if treeSize == 0 {
		// Do not insert fake entries into an empty tree
		if fake {
			return nil, nil, errors.New("cannot insert fake entries into an empty tree")
		}
		for i, entry := range entries {
			sequenced = append(sequenced, &cachedLogEntry{
				inner: &pb.LogEntry{
					Index:               entry.Index,
					Copath:              nil,
					FirstUpdatePosition: treeSize + uint64(i),
					Leaf:                &pb.LeafNode{Ctr: 0, Commitment: entry.Commitment},
				},
				aesKey: t.aesKey,
			})
		}
	} else {
		var err error
		sequenced, err = t.sequence(treeSize, entries, fake)
		if err != nil {
			return nil, nil, err
		}
	}

	// All the entries in the `sequenced` slice are constructed as if they're
	// going to be treeSize+1 of the tree. Update them so that they're in order.
	for i := 1; i < len(sequenced); i++ {
		search := &Search{index: sequenced[i].inner.Index, ptr: treeSize - 1 + uint64(i)}
		ptr := i - 1
		for {
			// Search the prefix tree of the log entry associated with `ptr`.
			// `ptr` starts out as the previous log entry but can jump back in time to anywhere in the log tree.
			res := search.step(false, sequenced[ptr])
			switch res := res.(type) {
			case uint64:
				// If the next step of the search jumps to a previous entry in the sequencing batch,
				// we can grab that log entry from the `sequenced` slice and continue our search
				if res >= treeSize {
					ptr = int(res - treeSize)
					continue
				}
				// Otherwise, the search jumped to a log entry less than the starting log tree size before the batch update.
				// The copath only needs to be updated through the prefix tree level where the search jumped;
				// after this level, the copath that was sequenced is up-to-date.
				sequenced[i].inner.Copath = combineCopaths(search.copath, sequenced[i].inner.Copath)
				for j := 0; j < len(search.copath); j++ {
					sequenced[i].parents[j] = nil
				}
			// We'd hit this if we update a real index twice or more in the batch
			case *cachedLogEntry:
				sequenced[i].inner.Copath = res.inner.Copath
				sequenced[i].inner.FirstUpdatePosition = res.inner.FirstUpdatePosition
				sequenced[i].inner.Leaf.Ctr = res.inner.Leaf.Ctr + 1

				sequenced[i].seed = res.seed
				sequenced[i].standIns = res.standIns
				sequenced[i].parents = [256][]byte{}
			// We'd hit this if we update an index for the first time and encounter the
			// terminal search step with an entry in the batch
			case *failedSearch:
				sequenced[i].inner.Copath = combineCopaths(res.copath, sequenced[i].inner.Copath)
				for j := 0; j < len(res.copath); j++ {
					sequenced[i].parents[j] = nil
				}
			default:
				panic("unreachable")
			}
			// Unless we jump to a previous log entry within the batch, we know we have the most up-to-date
			// copath for the current entry and can break out of the inner for loop
			break
		}

		// Fix precompute32, if it was changed by final sequencing.
		sequenced[i].precompute()
	}

	// Compute output and write to database.
	var (
		roots [][]byte
		srs   []*SearchResult
	)
	for i, entry := range sequenced {
		raw, err := proto.Marshal(entry.inner)
		if err != nil {
			return nil, nil, err
		}
		t.tx.Put(treeSize+uint64(i), raw)

		roots = append(roots, entry.rollup(0))

		// We don't care about search results for fake updates
		if !fake {
			srs = append(srs, &SearchResult{
				Proof:   entry.getCopath(),
				Counter: entry.inner.Leaf.Ctr,

				FirstUpdatePosition:  entry.inner.FirstUpdatePosition,
				LatestUpdatePosition: treeSize + uint64(i),
				Commitment:           entry.inner.Leaf.Commitment,
			})
		}
	}
	return roots, srs, nil
}

// Insert adds a new index to the tree or increments its counter if it already
// exists, and returns the new root and search result.
func (t *Tree) Insert(treeSize uint64, index, commitment []byte, fake bool) ([]byte, *SearchResult, error) {
	roots, srs, err := t.BatchInsert(treeSize, []Entry{{index, commitment}}, fake)
	if err != nil {
		return nil, nil, err
	}
	return roots[0], srs[0], nil
}

// LogEntries returns the stored log entries for the requested range.
func (t *Tree) LogEntries(start, end uint64) ([]*pb.LogEntry, [][]byte, [][]byte, error) {
	var ids []uint64
	for i := start; i < end; i++ {
		ids = append(ids, i)
	}
	raws, err := t.tx.BatchGet(ids)
	if err != nil {
		return nil, nil, nil, err
	}
	var (
		data           []*pb.LogEntry
		seeds          [][]byte
		prevSeedNeeded []uint64
	)
	for _, id := range ids {
		raw, ok := raws[id]
		if !ok {
			return nil, nil, nil, errors.New("not all expected data was provided")
		}
		entry := &pb.LogEntry{}
		if err := proto.Unmarshal(raw, entry); err != nil {
			return nil, nil, nil, err
		}
		data = append(data, entry)
		seeds = append(seeds, computeSeed(t.aesKey, entry.FirstUpdatePosition))

		// Log entries that replace a stand-in hash require us to look up the seed that was
		// used to generate the hash, for the purpose of computing AuditorProofs.
		// Specifically, these are log entries for:
		//   - a fake update
		//   - a real update to a search key for the first time
		if id == 0 {
			// Previous seed is never needed for first log entry.
		} else if entry.Leaf == nil && len(entry.Copath) > 0 {
			prevSeedNeeded = append(prevSeedNeeded, id)
		} else if entry.Leaf != nil && entry.Leaf.Ctr == 0 {
			prevSeedNeeded = append(prevSeedNeeded, id)
		}
	}

	var searches []*Search
	for _, id := range prevSeedNeeded {
		search, err := t.BatchSearch(id, pad(data[id-start].Index))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("creating search: %w", err)
		}
		searches = append(searches, search)
	}
	_, results, err := newSearchBatch(t.aesKey, t.tx, searches).exec(false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("running search: %w", err)
	}

	prevSeeds := make([][]byte, len(ids))
	for i, log := range data {
		if (start > 0 || i > 0) && log.Leaf == nil && len(log.Copath) == 0 {
			prevSeeds[i] = computeSeed(t.aesKey, start+uint64(i-1))
		}
	}
	for i, id := range prevSeedNeeded {
		switch res := results[i].(type) {
		case *failedSearch:
			// The previous seed for an entry is calculated from
			// the fixed AES key and the firstUpdatePosition of the index
			// that created the stand-in hash replaced by the entry
			prevSeeds[id-start] = computeSeed(t.aesKey, res.firstUpdatePosition)
		default:
			panic("unreachable")
		}
	}

	return data, seeds, prevSeeds, nil
}

func pad(in []byte) []byte {
	out := make([]byte, IndexLength)
	copy(out, in)
	return out
}
