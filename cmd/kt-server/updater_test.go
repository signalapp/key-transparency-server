package main

import (
	"crypto/rand"
	"testing"

	"github.com/signalapp/keytransparency/tree/transparency"
	"github.com/signalapp/keytransparency/tree/transparency/pb"
	"github.com/signalapp/keytransparency/tree/transparency/test"
	"github.com/stretchr/testify/assert"
)

func TestCollectBatch(t *testing.T) {
	tests := []struct {
		name                      string
		setupChannel              func() chan updateRequest
		setupTree                 func(t *testing.T) *transparency.Tree
		expectedNonTombstoneCount int
		expectTombstone           bool
	}{
		{
			name: "empty channel returns empty batch",
			setupChannel: func() chan updateRequest {
				return make(chan updateRequest, 10)
			},
			setupTree:                 newTree(),
			expectedNonTombstoneCount: 0,
			expectTombstone:           false,
		},
		{
			name: "single non-tombstone request",
			setupChannel: func() chan updateRequest {
				ch := make(chan updateRequest, 10)
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value1")
				return ch
			},
			setupTree:                 newTree(),
			expectedNonTombstoneCount: 1,
			expectTombstone:           false,
		},
		{
			name: "multiple non-tombstone requests batched together",
			setupChannel: func() chan updateRequest {
				ch := make(chan updateRequest, 10)
				for i := 0; i < 5; i++ {
					ch <- makeNonTombstoneRequest(generateRandomIndex(), "value")
				}
				return ch
			},
			setupTree:                 newTree(),
			expectedNonTombstoneCount: 5,
			expectTombstone:           false,
		},
		{
			name: "stops at tombstone and returns it separately",
			setupChannel: func() chan updateRequest {
				ch := make(chan updateRequest, 10)
				// Add 3 regular updates
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value1")
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value2")
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value3")
				// Add tombstone
				ch <- makeTombstoneRequest(generateRandomIndex())
				// Add more updates that should not be processed
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value5")
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value6")
				return ch
			},
			setupTree:                 newTree(),
			expectedNonTombstoneCount: 3,
			expectTombstone:           true,
		},
		{
			name: "first request is tombstone",
			setupChannel: func() chan updateRequest {
				ch := make(chan updateRequest, 10)
				ch <- makeTombstoneRequest(generateRandomIndex())
				// Add more requests that should not be processed
				ch <- makeNonTombstoneRequest(generateRandomIndex(), "value2")
				return ch
			},
			setupTree:                 newTree(),
			expectedNonTombstoneCount: 0,
			expectTombstone:           true,
		},
		{
			name: "all tombstone updates, returns first one",
			setupChannel: func() chan updateRequest {
				ch := make(chan updateRequest, 10)
				ch <- makeTombstoneRequest(generateRandomIndex())
				ch <- makeTombstoneRequest(generateRandomIndex())
				ch <- makeTombstoneRequest(generateRandomIndex())
				return ch
			},
			setupTree:                 newTree(),
			expectedNonTombstoneCount: 0,
			expectTombstone:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := tt.setupChannel()

			reqs, tombstone := collectUpdateBatch(ch)

			assert.Equal(t, tt.expectedNonTombstoneCount, len(reqs),
				"unexpected number of requests in batch")

			if tt.expectTombstone {
				assert.NotNil(t, tombstone,
					"expected tombstone update but got nil")
				assert.True(t, isTombstoneUpdate(tombstone.req.Req),
					"returned update is not a tombstone")
			} else {
				assert.Nil(t, tombstone,
					"expected no tombstone but got one")
			}
		})
	}
}

func newTree() func(t *testing.T) *transparency.Tree {
	return func(t *testing.T) *transparency.Tree {
		tree, _, _, _ := test.NewTree(t, transparency.ContactMonitoring)
		return tree
	}
}

func generateRandomIndex() [32]byte {
	var searchKey [32]byte
	rand.Read(searchKey[:])
	return searchKey
}

func makeNonTombstoneRequest(index [32]byte, value string) updateRequest {
	return updateRequest{
		req: &transparency.PreUpdateState{
			Index: index,
			Value: []byte(value),
		},
		res: make(chan updateResponse, 1),
	}
}

func makeTombstoneRequest(index [32]byte) updateRequest {
	return updateRequest{
		req: &transparency.PreUpdateState{
			Index: index,
			Req: &pb.UpdateRequest{
				Value: tombstoneBytes,
			},
		},
		res: make(chan updateResponse, 1),
	}
}
