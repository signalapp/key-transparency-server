//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pb/transparency.proto

// Package transparency implements a transparency tree that supports blinded
// searches and efficient auditing.
package transparency

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	stdmath "math"
	"slices"
	"time"

	"github.com/hashicorp/go-metrics"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/signalapp/keytransparency/crypto/commitments"
	"github.com/signalapp/keytransparency/crypto/vrf"
	edvrf "github.com/signalapp/keytransparency/crypto/vrf/ed25519"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/log"
	"github.com/signalapp/keytransparency/tree/prefix"
	prefixpb "github.com/signalapp/keytransparency/tree/prefix/pb"
	"github.com/signalapp/keytransparency/tree/transparency/math"
	"github.com/signalapp/keytransparency/tree/transparency/pb"
)

// DeploymentMode specifies the way that a transparency log is deployed.
type DeploymentMode uint8

const (
	ContactMonitoring DeploymentMode = iota + 1
	ThirdPartyManagement
	ThirdPartyAuditing
)

var (
	ErrInvalidArgument                   = errors.New("invalid request argument")
	ErrOutOfRange                        = errors.New("querying past end of log")
	ErrFailedPrecondition                = errors.New("failed precondition")
	ErrDuplicateUpdate                   = errors.New("duplicate update")
	ErrTombstoneIndexNotFound            = errors.New("tombstone index not found")
	ErrTombstoneUnexpectedPreUpdateValue = errors.New("tombstone unexpected pre-update value")
)

type ErrAuditorSignatureVerificationFailed struct {
	dataToBeSigned           []byte
	auditorPublicKey         ed25519.PublicKey
	auditorProvidedSignature []byte
}

func (e *ErrAuditorSignatureVerificationFailed) Error() string {
	return fmt.Sprintf("auditor signature verification failed.\ndataToBeSigned: %x\n, auditorPublicKey:%x\n, auditorSig: %x",
		e.dataToBeSigned, e.auditorPublicKey, e.auditorProvidedSignature)
}

// PrivateConfig wraps all of the cryptographic keys needed to operate a
// transparency tree.
type PrivateConfig struct {
	Mode         DeploymentMode
	SigKey       ed25519.PrivateKey
	AuditorKeys  map[string]ed25519.PublicKey
	VrfKey       vrf.PrivateKey
	PrefixAesKey []byte
	OpeningKey   []byte
}

func (c *PrivateConfig) Public() *PublicConfig {
	vrfKey, err := edvrf.NewVRFVerifier(c.VrfKey.Public().([]byte))
	if err != nil {
		panic(err)
	}
	return &PublicConfig{
		Mode:        c.Mode,
		SigKey:      c.SigKey.Public().(ed25519.PublicKey),
		AuditorKeys: c.AuditorKeys,
		VrfKey:      vrfKey,
	}
}

// PublicConfig wraps the cryptographic keys needed to interact with a
// transparency tree.
type PublicConfig struct {
	Mode        DeploymentMode
	SigKey      ed25519.PublicKey
	AuditorKeys map[string]ed25519.PublicKey
	VrfKey      vrf.PublicKey
}

// Tree is an implementation of a transparency tree that handles all state
// management, the evaluation of a VRF, and generating/opening commitments.
type Tree struct {
	config     *PrivateConfig
	tx         db.TransparencyStore
	logTree    *log.Tree
	prefixTree *prefix.Tree

	cacheControl *db.PrefixCacheControl

	latest   *db.TransparencyTreeHead
	auditors map[string]*db.AuditorTreeHead
}

func NewTree(config *PrivateConfig, tx db.TransparencyStore) (*Tree, error) {
	latest, auditors, err := tx.GetHead()
	if err != nil {
		return nil, err
	}
	cacheControl := db.NewPrefixCacheControl(tx.PrefixStore())

	return &Tree{
		config:     config,
		tx:         tx,
		logTree:    log.NewTree(tx.LogStore()),
		prefixTree: prefix.NewTree(config.PrefixAesKey, cacheControl),

		cacheControl: cacheControl,

		latest:   latest,
		auditors: auditors,
	}, nil
}

func (t *Tree) GetTransparencyTreeHead() *db.TransparencyTreeHead {
	return t.latest
}

func (t *Tree) GetLogTree() *log.Tree                   { return t.logTree }
func (t *Tree) GetCacheControl() *db.PrefixCacheControl { return t.cacheControl }

func (t *Tree) fullTreeHead(req *pb.Consistency) (*pb.FullTreeHead, error) {
	// Get consistency proof between last tree head and this one, if requested.
	var (
		last          [][]byte
		distinguished [][]byte
	)
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "consistency cannot be nil")
	}
	if req.Last != nil && *req.Last != t.latest.TreeSize {
		if *req.Last > t.latest.TreeSize {
			return nil, status.Error(codes.InvalidArgument, "last observed non-distinguished tree size is greater than current tree size")
		}
		if *req.Last == 0 {
			return nil, status.Error(codes.InvalidArgument, "last observed non-distinguished tree size must be greater than zero")
		}
		temp, err := t.logTree.GetConsistencyProof(*req.Last, t.latest.TreeSize)
		if err != nil {
			return nil, err
		}
		last = temp
	}
	if req.Distinguished != nil && *req.Distinguished != t.latest.TreeSize {
		if *req.Distinguished > t.latest.TreeSize {
			return nil, status.Error(codes.InvalidArgument, "last observed distinguished tree size is greater than current tree size")
		}
		if *req.Distinguished == 0 {
			return nil, status.Error(codes.InvalidArgument, "last observed distinguished tree size must be greater than zero")
		}
		temp, err := t.logTree.GetConsistencyProof(*req.Distinguished, t.latest.TreeSize)
		if err != nil {
			return nil, err
		}
		distinguished = temp
	}

	// Build the auditor tree head(s), if we're using third-party auditing.
	var auditorTreeHeads []*pb.FullAuditorTreeHead
	if len(t.auditors) > 0 {
		for auditorName, auditorTreeHead := range t.auditors {
			auditorPublicKey := t.config.AuditorKeys[auditorName]
			if len(auditorPublicKey) == 0 {
				return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("no auditor public key for auditor %s", auditorName))
			}
			pbAuditorTreeHead := &pb.FullAuditorTreeHead{
				TreeHead: &pb.AuditorTreeHead{
					TreeSize:  auditorTreeHead.TreeSize,
					Timestamp: auditorTreeHead.Timestamp,
					Signature: auditorTreeHead.Signature,
				},
				PublicKey: auditorPublicKey,
			}

			if auditorTreeHead.TreeSize < t.latest.TreeSize {
				pbAuditorTreeHead.RootValue = auditorTreeHead.RootValue
				pbAuditorTreeHead.Consistency = auditorTreeHead.Consistency
			}
			auditorTreeHeads = append(auditorTreeHeads, pbAuditorTreeHead)
		}
	}

	var signatures []*pb.Signature
	for _, sig := range t.latest.Signatures {
		signature := &pb.Signature{
			Signature:        sig.Signature,
			AuditorPublicKey: sig.AuditorPublicKey,
		}
		signatures = append(signatures, signature)
	}

	return &pb.FullTreeHead{
		TreeHead: &pb.TreeHead{
			TreeSize:   t.latest.TreeSize,
			Timestamp:  t.latest.Timestamp,
			Signatures: signatures,
		},
		Last:                 last,
		Distinguished:        distinguished,
		FullAuditorTreeHeads: auditorTreeHeads,
	}, nil
}

func (t *Tree) updatedAuditorHeads(treeSize uint64) (map[string]*db.AuditorTreeHead, error) {
	if t.auditors == nil {
		return nil, nil
	}
	auditors := make(map[string]*db.AuditorTreeHead)
	for auditorName, auditorTreeHead := range t.auditors {
		var consistency [][]byte
		if treeSize > auditorTreeHead.TreeSize {
			var err error
			consistency, err = t.logTree.GetConsistencyProof(auditorTreeHead.TreeSize, treeSize)
			if err != nil {
				return nil, err
			}
		}
		auditor := &db.AuditorTreeHead{
			AuditorTransparencyTreeHead: db.AuditorTransparencyTreeHead{
				TreeSize:  auditorTreeHead.TreeSize,
				Timestamp: auditorTreeHead.Timestamp,
				Signature: auditorTreeHead.Signature,
			},
			RootValue:   auditorTreeHead.RootValue,
			Consistency: consistency,
		}
		auditors[auditorName] = auditor
	}
	return auditors, nil
}

func (t *Tree) search(index [32]byte, firstUpdatePosition, latestUpdatePosition uint64) (*pb.SearchProof, error) {
	// Determine the path of our binary search.
	ids, err := searchPath(firstUpdatePosition, latestUpdatePosition, t.latest.TreeSize)
	if err != nil {
		return nil, err
	}

	// Batch search prefix trees along this path.
	var searches []*prefix.Search
	for _, id := range ids {
		search, err := t.prefixTree.BatchSearch(id+1, index[:])
		if err != nil {
			return nil, err
		}
		searches = append(searches, search)
	}
	results, err := t.prefixTree.BatchExec(searches)
	if err != nil {
		return nil, err
	}

	// Convert the search results into SearchStep structures.
	var searchSteps []*pb.ProofStep
	for i, res := range results {
		commitment := res.Commitment
		if commitment == nil {
			commitment, err = fakeCommitment(t.config.OpeningKey, ids[i])
			if err != nil {
				return nil, err
			}
		}
		searchSteps = append(searchSteps, &pb.ProofStep{
			Prefix:     &pb.PrefixProof{Proof: res.Proof, Counter: res.Counter},
			Commitment: commitment,
		})
	}

	// Fetch batch inclusion proof.
	inclusion, err := t.logTree.GetBatchProof(ids, t.latest.TreeSize)
	if err != nil {
		return nil, err
	}

	return &pb.SearchProof{
		Pos:       firstUpdatePosition,
		Steps:     searchSteps,
		Inclusion: inclusion,
	}, nil
}

// Search takes a TreeSearchRequest from a user as input that contains a search key
// to search for. It returns a TreeSearchResponse with the key's value, and a cryptographic proof that the response is valid.
func (t *Tree) Search(req *pb.TreeSearchRequest) (*pb.TreeSearchResponse, error) {
	index, vrfProof := t.config.VrfKey.ECVRFProve(req.SearchKey)

	// Find the position of the first occurrence of the index in the log, and the
	// position of the most recent occurrence of the index in the log.
	res, err := t.prefixTree.Search(t.latest.TreeSize, index[:])
	if err != nil {
		return nil, err
	}

	firstUpdatePosition, latestUpdatePosition := res.FirstUpdatePosition, res.LatestUpdatePosition

	// Fetch the search proof and the update value.
	searchProof, err := t.search(index, firstUpdatePosition, latestUpdatePosition)
	if err != nil {
		return nil, err
	}
	raw, err := t.tx.Get(latestUpdatePosition)
	if err != nil {
		return nil, err
	}
	value, err := unmarshalUpdateValue(raw)
	if err != nil {
		return nil, err
	}

	// Build the final SearchResponse to return.
	fth, err := t.fullTreeHead(req.Consistency)
	if err != nil {
		return nil, err
	}
	return &pb.TreeSearchResponse{
		TreeHead: fth,
		VrfProof: vrfProof,
		Search:   searchProof,

		Opening: computeOpening(t.config.OpeningKey, latestUpdatePosition),
		Value:   value,
	}, nil
}

type previousValue struct {
	pos   uint64
	value []byte
}

type PreUpdateState struct {
	Req      *pb.UpdateRequest
	Index    [32]byte
	vrfProof []byte
	Value    []byte

	cache map[uint64][]byte
	prev  *previousValue
}

// PreUpdate does any calculations required for an Update operation that can be
// performed ahead of entering the critical path.
func (t *Tree) PreUpdate(req *pb.UpdateRequest) (*PreUpdateState, error) {
	index, vrfProof := t.config.VrfKey.ECVRFProve(req.SearchKey)
	currValue, err := marshalUpdateValue(&pb.UpdateValue{Value: req.Value})
	if err != nil {
		return nil, err
	}

	// Lookup this index in the prefix tree to build a cache of what prefix tree entries will
	// be needed.
	t.cacheControl.StartTracking()

	pos, err := t.prefixTree.Trace(t.latest.TreeSize, [][]byte{index[:]})
	if err != nil {
		metrics.IncrCounterWithLabels([]string{"preupdate.error"}, 1, []metrics.Label{{Name: "source", Value: "prefix_tree"}})
		t.cacheControl.StopTracking()
		return nil, err
	}

	// If this index exists in the log, load its current value into cache.
	var prev *previousValue
	if pos[0] != stdmath.MaxUint64 {
		value, err := t.tx.Get(pos[0])
		if err != nil {
			metrics.IncrCounterWithLabels([]string{"preupdate.error"}, 1, []metrics.Label{{Name: "source", Value: "transparency_tree"}})
			t.cacheControl.StopTracking()
			return nil, err
		}
		prev = &previousValue{pos: pos[0], value: value}
	}

	cache := t.cacheControl.ExportCache()
	// t.cacheControl.StopTracking() -- This is called in PostUpdate because
	// it's helpful to keep the cache around until then. This may need to be
	// called explicitly if there are more methods being called on the tree
	// between PreUpdate and PostUpdate.

	return &PreUpdateState{req, index, vrfProof, currValue, cache, prev}, nil
}

type PostUpdateState struct {
	pre     *PreUpdateState
	opening []byte
	sr      *prefix.SearchResult
	head    *db.TransparencyTreeHead

	err error
}

func (p *PostUpdateState) Err() error {
	return p.err
}

// PostUpdate does any calculations required to finish an Update operation that
// can be performed after exiting the critical path.
func (t *Tree) PostUpdate(state *PostUpdateState) (*pb.UpdateResponse, error) {
	if state.err != nil {
		return nil, state.err
	}

	t.latest = state.head

	// Build a search proof for the newly-added value.
	searchProof, err := t.search(state.pre.Index, state.sr.FirstUpdatePosition, state.sr.LatestUpdatePosition)
	if err != nil {
		return nil, err
	}
	t.cacheControl.StopTracking()

	// Build the final UpdateResponse to return.
	fth, err := t.fullTreeHead(state.pre.Req.Consistency)
	if err != nil {
		return nil, err
	}
	return &pb.UpdateResponse{
		TreeHead: fth,
		VrfProof: state.pre.vrfProof,
		Search:   searchProof,

		Opening: state.opening,
	}, nil
}

// UpdateExistingIndexWithTombstoneValue handles "tombstone updates", updates that overwrite
// an existing index to point to a tombstone value to reflect the state of the world when a user
// deletes an account or changes their phone number or username.
// It looks up the current mapped value of the index and checks that it matches the expected mapped value
// to prevent incorrect state resulting from a race between the tombstone update and another user claiming
// the old identifier.
func (t *Tree) UpdateExistingIndexWithTombstoneValue(state *PreUpdateState) (*PostUpdateState, error) {
	result, err := t.prefixTree.Search(t.latest.TreeSize, state.Index[:])
	if err != nil {
		if gprcError, ok := status.FromError(err); ok && gprcError.Code() == codes.NotFound {
			return nil, ErrTombstoneIndexNotFound
		}
		return nil, err
	}

	raw, err := t.tx.Get(result.LatestUpdatePosition)
	if err != nil {
		return nil, err
	}
	updateValue, err := unmarshalUpdateValue(raw)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(updateValue.GetValue(), state.Req.GetExpectedPreUpdateValue()) {
		// We would hit this case if another user claimed the old identifier, and their update made it into the log
		// before the tombstone update did. Abort the tombstone update.
		return nil, ErrTombstoneUnexpectedPreUpdateValue
	}

	postUpdateState, err := t.BatchUpdate([]*PreUpdateState{state})
	if err != nil {
		return nil, err
	}
	return postUpdateState[0], nil

}

// BatchUpdate takes in a batch of PreUpdateStates, each containing a search key
// and the key's new value, and applies the updates to the log.
func (t *Tree) BatchUpdate(states []*PreUpdateState) ([]*PostUpdateState, error) {
	out := make([]*PostUpdateState, len(states))

	// Collate the prefix tree data cached by each update.
	for _, state := range states {
		err := t.cacheControl.ImportCache(state.cache)
		if err != nil {
			return nil, err
		}
	}
	defer t.cacheControl.StopTracking()

	// Collate all of the provided values for the different indices for easier
	// access later.
	logEntryToVal := make(map[uint64][]byte)
	for _, state := range states {
		if state.prev != nil {
			if other, ok := logEntryToVal[state.prev.pos]; !ok {
				logEntryToVal[state.prev.pos] = state.prev.value
			} else if !bytes.Equal(other, state.prev.value) {
				return nil, errors.New("different values given for same log entry")
			}
		}
	}

	// Our goal in the entire remainder of this function is to filter out update
	// requests that would set an index to the same value that it already has.
	// While not strictly required for the integrity of the log, these updates
	// would make it impossible for clients to monitor a key for unexpected changes.

	// First, check if we can find `states` elements that duplicate a
	// previous element. Filter them out if so.
	firstUpdate := make(map[[32]byte]int) // First observed update for an index.
	lastUpdate := make(map[[32]byte]int)  // Last observed update for an index.

	for i, state := range states {
		if _, ok := firstUpdate[state.Index]; !ok {
			firstUpdate[state.Index] = i
		}
		prev, ok := lastUpdate[state.Index]
		if ok && bytes.Equal(states[prev].Value, state.Value) {
			out[i] = &PostUpdateState{err: ErrDuplicateUpdate}
			continue
		}
		lastUpdate[state.Index] = i
	}

	// The `firstUpdate` map maps every index that we're updating to the
	// position of the first update request for that index in `states`. Check if
	// these update requests duplicate the currently stored value in the
	// database.
	indices := make([][]byte, 0, len(firstUpdate))
	statesPos := make([]int, 0, len(firstUpdate))
	for index, i := range firstUpdate {
		indices = append(indices, index[:])
		statesPos = append(statesPos, i)
	}
	// Search the prefix tree again to ensure that we have the most up-to-date
	// log entry for each index.
	logEntries, err := t.prefixTree.Trace(t.latest.TreeSize, indices)
	if err != nil {
		return nil, err
	}
	for i, pos := range logEntries {
		if pos == stdmath.MaxUint64 { // The index doesn't exist yet.
			continue
		}
		// If the log entry we need was provided as part of the request cache,
		// check the new value against the cache.
		prevVal, ok := logEntryToVal[pos]
		if ok {
			if bytes.Equal(states[statesPos[i]].Value, prevVal) {
				out[statesPos[i]] = &PostUpdateState{err: ErrDuplicateUpdate}
			}
			continue
		}
		// The log entry we need wasn't provided, which means the index was
		// updated between when the update request was generated and this point.
		// It's likely still cached -- we'll see a performance hit if not.
		val, err := t.tx.Get(pos)
		if err != nil {
			return nil, err
		} else if bytes.Equal(states[statesPos[i]].Value, val) {
			out[statesPos[i]] = &PostUpdateState{err: ErrDuplicateUpdate}
		}
	}

	// Now we need to call batchUpdate with the remaining update requests that
	// are not duplicate and weave the results back into our full `out` slice.
	remainingStates := make([]*PreUpdateState, 0, len(states))
	nilIndices := make([]int, 0, len(states))
	for i, post := range out {
		if post == nil {
			remainingStates = append(remainingStates, states[i])
			nilIndices = append(nilIndices, i)
		}
	}
	results, err := t.batchUpdate(remainingStates)
	if err != nil {
		return nil, err
	}
	for i, idx := range nilIndices {
		out[idx] = results[i]
	}
	return out, nil
}

func (t *Tree) batchUpdate(states []*PreUpdateState) ([]*PostUpdateState, error) {
	if len(states) == 0 {
		return nil, nil
	}

	// Prepare the commitment opening and prefix tree entry for each change.
	openings := make([][]byte, len(states))
	entries := make([]prefix.Entry, len(states))
	for i, state := range states {
		treeSize := t.latest.TreeSize + uint64(i)

		// Compute the commitment opening and the commitment itself.
		opening := computeOpening(t.config.OpeningKey, treeSize)
		commitment, err := commitments.Commit(state.Req.SearchKey, state.Value, opening)
		if err != nil {
			return nil, err
		}

		openings[i] = opening
		entries[i] = prefix.Entry{Index: state.Index[:], Commitment: commitment}

		// Add journal entry.
		t.tx.Put(treeSize, state.Value)
	}

	// Update indexes in the prefix tree.
	roots, srs, err := t.prefixTree.BatchInsert(t.latest.TreeSize, entries, false)
	if err != nil {
		return nil, err
	}

	// Insert into the log tree.
	values := make([][]byte, len(states))
	for i := range states {
		values[i] = leafHash(roots[i], entries[i].Commitment)
	}
	logRoot, err := t.logTree.BatchAppend(t.latest.TreeSize, values)
	if err != nil {
		return nil, err
	}

	// Produce new signed tree head.
	head, err := signNewHead(t.config, t.latest.TreeSize+uint64(len(states)), logRoot)
	if err != nil {
		return nil, err
	}

	// Store the new tree head and commit all pending changes.
	var auditors map[string]*db.AuditorTreeHead
	if auditors, err = t.updatedAuditorHeads(head.TreeSize); err != nil {
		return nil, err
	} else if err := t.tx.Commit(head, auditors); err != nil {
		return nil, err
	}
	t.latest = head
	t.auditors = auditors

	// Build output and return.
	out := make([]*PostUpdateState, len(states))
	for i, state := range states {
		out[i] = &PostUpdateState{state, openings[i], srs[i], head, nil}
	}
	return out, nil
}

// UpdateSimple does a full Update operation in a simple one-shot API call.
func (t *Tree) UpdateSimple(req *pb.UpdateRequest) (*pb.UpdateResponse, error) {
	pre, err := t.PreUpdate(req)
	if err != nil {
		return nil, err
	}
	post, err := t.BatchUpdate([]*PreUpdateState{pre})
	if err != nil {
		return nil, err
	}
	return t.PostUpdate(post[0])
}

func (t *Tree) CanFakeUpdate() bool { return t.latest.TreeSize > 0 }

// BatchUpdateFake inserts the specified number of fake updates into the log.
func (t *Tree) BatchUpdateFake(numUpdates int) error {
	// Generate fake log entries
	fakeEntries := make([]prefix.Entry, numUpdates)

	for i := 0; i < numUpdates; i++ {
		commitment, err := fakeCommitment(t.config.OpeningKey, t.latest.TreeSize+uint64(i))
		if err != nil {
			return err
		}

		index := make([]byte, prefix.IndexLength)
		if _, err := rand.Read(index); err != nil {
			return fmt.Errorf("getting randomness: %w", err)
		}
		fakeEntries[i] = prefix.Entry{Index: index[:], Commitment: commitment}
	}

	// Update indexes in the prefix tree.
	roots, _, err := t.prefixTree.BatchInsert(t.latest.TreeSize, fakeEntries, true)
	if err != nil {
		return err
	}

	// Insert into the log tree.
	values := make([][]byte, numUpdates)
	for i := 0; i < numUpdates; i++ {
		values[i] = leafHash(roots[i], fakeEntries[i].Commitment)
	}

	logRoot, err := t.logTree.BatchAppend(t.latest.TreeSize, values)
	if err != nil {
		return err
	}

	// Produce new signed tree head.
	head, err := signNewHead(t.config, t.latest.TreeSize+uint64(numUpdates), logRoot)
	if err != nil {
		return err
	}
	// Store the new tree head and commit all pending changes.
	var auditors map[string]*db.AuditorTreeHead
	if auditors, err = t.updatedAuditorHeads(head.TreeSize); err != nil {
		return err
	} else if err := t.tx.Commit(head, auditors); err != nil {
		return err
	}
	t.latest = head
	t.auditors = auditors
	return nil
}

// Monitor takes a MonitorRequest from a user as input, containing a list of
// search keys that the user would like to monitor. It returns a MonitorResponse
// proving that the requested keys are still properly included in the log.
func (t *Tree) Monitor(req *pb.MonitorRequest) (*pb.MonitorResponse, error) {

	// Do as much verification on the monitoring request as we can, and prepare
	// a batch database request to resolve the rest of the verification.
	var verifySearches []*prefix.Search
	vrfOutput := make(map[string][32]byte) // Both detects duplicates and stores the VRF output of each key.

	for _, key := range req.Keys {
		search, err := t.verifyMonitorKey(vrfOutput, key)
		if err != nil {
			return nil, err
		}
		verifySearches = append(verifySearches, []*prefix.Search{search}...)
	}

	verifyResults, err := t.prefixTree.BatchExec(verifySearches)
	if err != nil {
		return nil, err
	}

	// Determine which database lookups are required to build the monitor response.
	var monitorSearches []*prefix.Search
	var monitorSizes []int
	var monitorEntries []uint64

	for i, key := range req.Keys {
		searches, entries, err := t.finishMonitoring(vrfOutput[string(key.SearchKey)], key, verifyResults[i])
		if err != nil {
			return nil, err
		}
		monitorSearches = append(monitorSearches, searches...)
		monitorSizes = append(monitorSizes, len(searches))
		monitorEntries = append(monitorEntries, entries...)
	}

	monitorResults, err := t.prefixTree.BatchExec(monitorSearches)
	if err != nil {
		return nil, err
	}

	var proofs []*pb.MonitorProof
	start := 0

	for _, size := range monitorSizes {
		end := start + size

		var proof pb.MonitorProof
		for i, sr := range monitorResults[start:end] {
			commitment := sr.Commitment
			if commitment == nil {
				commitment, err = fakeCommitment(t.config.OpeningKey, monitorEntries[start+i])
				if err != nil {
					return nil, err
				}
			}
			proof.Steps = append(proof.Steps, &pb.ProofStep{
				Prefix:     &pb.PrefixProof{Proof: sr.Proof, Counter: sr.Counter},
				Commitment: commitment,
			})
		}

		proofs = append(proofs, &proof)
		start = end
	}

	// Get an inclusion proof for all of the entries accessed.
	dedup := make(map[uint64]struct{})
	for _, entry := range monitorEntries {
		dedup[entry] = struct{}{}
	}
	var entries []uint64
	for entry := range dedup {
		entries = append(entries, entry)
	}
	inclusion, err := t.logTree.GetBatchProof(entries, t.latest.TreeSize)
	if err != nil {
		return nil, err
	}

	// Build the final MonitorResponse structure to return.
	fth, err := t.fullTreeHead(req.Consistency)
	if err != nil {
		return nil, err
	}
	return &pb.MonitorResponse{
		TreeHead:  fth,
		Proofs:    proofs,
		Inclusion: inclusion,
	}, nil
}

// verifyMonitorKey does offline verification of a MonitorKey structure. It
// stores the VRF-output of the requested search key in `vrfOutput`, and returns
// the slice of database searches that will be required to finish verification.
func (t *Tree) verifyMonitorKey(vrfOutput map[string][32]byte, key *pb.MonitorKey) (*prefix.Search, error) {
	// Check if this key is a duplicate of a previous one.
	if _, ok := vrfOutput[string(key.SearchKey)]; ok {
		return nil, status.Error(codes.InvalidArgument, "cannot monitor duplicate keys")
	}

	// Verify the commitment index matches
	if 32 != len(key.CommitmentIndex) {
		return nil, status.Error(codes.InvalidArgument, "invalid commitment index")
	}
	index, _ := t.config.VrfKey.ECVRFProve(key.SearchKey)
	if 1 != subtle.ConstantTimeCompare(index[:], key.CommitmentIndex) {
		return nil, status.Error(codes.PermissionDenied, "commitment index does not match")
	}
	vrfOutput[string(key.SearchKey)] = index

	if key.EntryPosition >= t.latest.TreeSize {
		return nil, status.Error(codes.InvalidArgument, "monitoring request is malformed: entry is past end of tree")
	}
	// Note: The spec also says to check if any entries are less than the
	// first occurrence of the key in the log. If this happens, the batch
	// search will fail.

	// Lookup the search key in the specified prefix tree to ensure that the entry
	// is in its monitoring path
	search, err := t.prefixTree.BatchSearch(key.EntryPosition+1, index[:])
	if err != nil {
		return nil, err
	}

	return search, nil
}

// finishMonitoring does the remaining verification of a MonitorKey structure
// with the database output `res`. It returns the slice of database searches
// that will be required to build the MonitorResponse, and the slice of entry
// ids used (which will be used to compute a log inclusion proof).
func (t *Tree) finishMonitoring(index [32]byte, key *pb.MonitorKey, res *prefix.SearchResult) ([]*prefix.Search, []uint64, error) {
	// Verify that the entry is on the monitoring path of a "version" (counter value) of the key.
	if key.EntryPosition != res.LatestUpdatePosition {
		path := math.MonitoringPath(res.LatestUpdatePosition, res.FirstUpdatePosition, t.latest.TreeSize)
		if ok := slices.Contains(path, key.EntryPosition); !ok {
			return nil, nil, status.Error(codes.InvalidArgument, "monitoring request is malformed: entry not on monitoring path")
		}
	}

	var searches []*prefix.Search
	var entries []uint64

	// Return proofs for new nodes on the direct path of the provided entry, and
	// required entries on the frontier.
	for _, x := range math.FullMonitoringPath(key.EntryPosition, res.FirstUpdatePosition, t.latest.TreeSize) {
		search, err := t.prefixTree.BatchSearch(x+1, index[:])
		if err != nil {
			return nil, nil, err
		}
		searches = append(searches, search)
		entries = append(entries, x)
	}

	return searches, entries, nil
}

// Audit returns the set of AuditorUpdate structures that would need to be
// provided to a third-party auditor.
func (t *Tree) Audit(start, limit uint64) ([]*pb.AuditorUpdate, bool, error) {
	if start > t.latest.TreeSize {
		return nil, false, fmt.Errorf("%w: auditing can not start past end of tree", ErrOutOfRange)
	} else if start == t.latest.TreeSize {
		return nil, false, nil
	} else if limit > 1000 {
		return nil, false, fmt.Errorf("%w: max limit of 1000 entries per audit request", ErrInvalidArgument)
	}
	end := start + limit
	if end > t.latest.TreeSize {
		end = t.latest.TreeSize
	}
	logs, seeds, prevSeeds, err := t.prefixTree.LogEntries(start, end)
	if err != nil {
		return nil, false, err
	}

	// Construct auditor proofs.
	var proofs []*pb.AuditorProof
	for i, log := range logs {
		if start == 0 && i == 0 {
			proofs = append(proofs, &pb.AuditorProof{
				Proof: &pb.AuditorProof_NewTree_{
					NewTree: &pb.AuditorProof_NewTree{},
				},
			})
		} else if log.Leaf == nil && len(log.Copath) > 0 {
			proofs = append(proofs, &pb.AuditorProof{
				Proof: &pb.AuditorProof_DifferentKey_{
					DifferentKey: &pb.AuditorProof_DifferentKey{
						Copath:  simpleCopath(log.Copath),
						OldSeed: prevSeeds[i],
					},
				},
			})
		} else if log.Leaf.Ctr == 0 {
			proofs = append(proofs, &pb.AuditorProof{
				Proof: &pb.AuditorProof_DifferentKey_{
					DifferentKey: &pb.AuditorProof_DifferentKey{
						Copath:  simpleCopath(log.Copath),
						OldSeed: prevSeeds[i],
					},
				},
			})
		} else {
			proofs = append(proofs, &pb.AuditorProof{
				Proof: &pb.AuditorProof_SameKey_{
					SameKey: &pb.AuditorProof_SameKey{
						Copath:   simpleCopath(log.Copath),
						Counter:  log.Leaf.Ctr - 1,
						Position: log.FirstUpdatePosition,
					},
				},
			})
		}
	}

	var out []*pb.AuditorUpdate
	for i, log := range logs {
		var commitment []byte
		if log.Leaf == nil {
			commitment, err = fakeCommitment(t.config.OpeningKey, start+uint64(i))
			if err != nil {
				return nil, false, err
			}
		} else {
			commitment = log.Leaf.Commitment
		}

		index := make([]byte, 32) // Pad log.Index to 32 bytes if it's truncated.
		copy(index, log.Index)

		out = append(out, &pb.AuditorUpdate{
			Real:       log.Leaf != nil,
			Index:      index,
			Seed:       seeds[i],
			Commitment: commitment,
			Proof:      proofs[i],
		})
	}
	return out, end < t.latest.TreeSize, nil
}

func simpleCopath(copath []*prefixpb.ParentNode) [][]byte {
	out := make([][]byte, 0)
	for _, entry := range copath {
		out = append(out, entry.Hash)
	}
	return out
}

// SetAuditorHead is called when the third-party auditor (if using third-party
// auditing) submits a new version of its tree head.
func (t *Tree) SetAuditorHead(head *pb.AuditorTreeHead, auditorName string) error {
	if t.config.Mode != ThirdPartyAuditing {
		return fmt.Errorf("%w: tree is not in third-party auditing mode", ErrFailedPrecondition)
	} else if head == nil {
		return fmt.Errorf("%w: auditor tree head may not be nil", ErrInvalidArgument)
	}
	// Note: The below code mirrors the relevant section of verifyFullTreeHead.

	// Verify tree size.
	if head.TreeSize > t.latest.TreeSize {
		return fmt.Errorf("%w: auditor tree head may not be further along than service tree head", ErrInvalidArgument)
	} else if t.latest.TreeSize-head.TreeSize > entriesMaxBehind {
		return fmt.Errorf("%w: auditor tree head is too far behind service tree head", ErrInvalidArgument)
	} else if t.auditors[auditorName] != nil && head.TreeSize < t.auditors[auditorName].TreeSize {
		return fmt.Errorf("%w: auditor tree head can not be less than before", ErrInvalidArgument)
	}
	// Verify timestamp.
	now, then := time.Now().UnixMilli(), head.Timestamp
	if now > then && now-then > timeAuditorMaxBehind.Milliseconds() {
		return fmt.Errorf("%w: auditor timestamp is too far behind current time", ErrInvalidArgument)
	} else if now < then && then-now > timeMaxAhead.Milliseconds() {
		return fmt.Errorf("%w: auditor timestamp is too far ahead of current time", ErrInvalidArgument)
	} else if t.auditors[auditorName] != nil && head.Timestamp < t.auditors[auditorName].Timestamp {
		return fmt.Errorf("%w: auditor timestamp can not be less than before", ErrInvalidArgument)
	}

	// Verify signature
	root, err := t.logTree.GetRoot(head.TreeSize)
	if err != nil {
		return err
	}
	temp := &pb.FullAuditorTreeHead{TreeHead: head}
	if auditorPublicKey, ok := t.config.AuditorKeys[auditorName]; !ok {
		return fmt.Errorf("failed to get auditor public key for auditor: %s", auditorName)
	} else if err := verifyAuditorTreeHead(t.config.Public(), temp, root, auditorPublicKey); err != nil {
		return err
	}

	// Build full AuditorTreeHead structure.
	var consistency [][]byte
	if head.TreeSize < t.latest.TreeSize {
		consistency, err = t.logTree.GetConsistencyProof(head.TreeSize, t.latest.TreeSize)
		if err != nil {
			return err
		}
	}
	auditor := &db.AuditorTreeHead{
		AuditorTransparencyTreeHead: db.AuditorTransparencyTreeHead{
			TreeSize:  head.TreeSize,
			Timestamp: head.Timestamp,
			Signature: head.Signature,
		},
		RootValue:   root,
		Consistency: consistency,
	}

	// Save the old value in case the database commit fails
	old, exists := t.auditors[auditorName]
	t.auditors[auditorName] = auditor

	if err := t.tx.Commit(t.latest, t.auditors); err != nil {
		if exists {
			t.auditors[auditorName] = old
		} else {
			delete(t.auditors, auditorName)
		}
		return err
	}

	return nil
}

// searchPath returns the set of ids that will be accessed by a binary search
// through the transparency tree for the entry associated with `latestUpdatePosition`.
// `firstUpdatePosition` is the position of the first occurrence of the index in the tree,
// `latestUpdatePosition` is the position of the most recent occurrence of the index in the tree, and
// `treeSize` is the current size of the tree.
func searchPath(firstUpdatePosition, latestUpdatePosition, treeSize uint64) ([]uint64, error) {
	var ids []uint64

	guide := mostRecentProofGuide(firstUpdatePosition, treeSize)

	for {
		done, err := guide.done()
		if err != nil {
			return nil, err
		} else if done {
			break
		}
		id := guide.next()
		if id < latestUpdatePosition {
			guide.insert(id, 0)
		} else {
			guide.insert(id, 1)
		}
		ids = append(ids, id)
	}

	return ids, nil
}
