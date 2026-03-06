//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/signalapp/keytransparency/cmd/internal/config"
	"github.com/signalapp/keytransparency/cmd/shared"
	"github.com/signalapp/keytransparency/db"
)

var (
	validAci2            = random(16)
	validAciIdentityKey2 = createDistinctValue(validAciIdentityKey1)
)

type mockLogUpdater struct {
	mock.Mock
}

func (m *mockLogUpdater) update(ctx context.Context, within string, key, value []byte, updateHandler *KtUpdateHandler, expectedPreUpdateValue []byte) (returnedErr error) {
	m.Called(ctx, within, key, value, updateHandler, expectedPreUpdateValue)
	return nil
}

type expectedUpdateInputs struct {
	key            []byte
	value          []byte
	preUpdateValue []byte
}

var testUpdateAciPairs = []testCase[aci]{
	// No change
	{
		&streamPair[aci]{
			Prev: &aci{
				ACI:            validAci1,
				ACIIdentityKey: validAciIdentityKey1,
			},
			Next: &aci{
				ACI:            validAci1,
				ACIIdentityKey: validAciIdentityKey1,
			},
		},
		0,
		[]expectedUpdateInputs{},
	},
	// Add ACI
	{
		&streamPair[aci]{
			Prev: nil,
			Next: &aci{
				ACI:            validAci1,
				ACIIdentityKey: validAciIdentityKey1,
			},
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.AciPrefix}, validAci1...), value: marshalValue(validAciIdentityKey1), preUpdateValue: nil},
		},
	},
	// Update ACI mapping
	{
		&streamPair[aci]{
			Prev: &aci{
				ACI:            validAci1,
				ACIIdentityKey: validAciIdentityKey1,
			},
			Next: &aci{
				ACI:            validAci1,
				ACIIdentityKey: validAciIdentityKey2,
			},
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.AciPrefix}, validAci1...), value: marshalValue(validAciIdentityKey2), preUpdateValue: nil},
		},
	},
	// Delete ACI
	{
		&streamPair[aci]{
			Prev: &aci{
				ACI:            validAci1,
				ACIIdentityKey: validAciIdentityKey1,
			},
			Next: nil,
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.AciPrefix}, validAci1...), value: tombstoneBytes, preUpdateValue: marshalValue(validAciIdentityKey1)},
		},
	},
}

func TestUpdateFromAciStream(t *testing.T) {
	testStreamUpdate[aci](t, testUpdateAciPairs, updateFromAciStream)
}

func TestLockSearchKey(t *testing.T) {
	const parallel = 5

	state := &shardState{}
	defer state.lockSearchKey([]byte("other"))()

	counter := 0
	output := make(chan int)
	for range parallel {
		go func() {
			defer state.lockSearchKey([]byte("label"))()
			output <- counter
			time.Sleep(1 * time.Millisecond)
			counter++
		}()
	}

	for i := range parallel {
		if res := <-output; res != i {
			t.Fatal("unexpected counter read")
		}
	}
}

type testCase[T SearchKey] struct {
	pair                 *streamPair[T]
	expectedNumUpdates   int
	expectedUpdateInputs []expectedUpdateInputs
}

func testStreamUpdate[T SearchKey](t *testing.T,
	pairs []testCase[T],
	updaterFunc func(context.Context, []byte, *shardState, *KtUpdateHandler, Updater) error) {
	mockConfig, _ := config.Read(mockConfigFile)
	mockTransparencyStore := db.NewMemoryTransparencyStore()
	updateRequestChannel := make(chan updateRequest)
	mockUpdateHandler := &KtUpdateHandler{
		config: mockConfig.APIConfig,
		tx:     mockTransparencyStore,
		ch:     updateRequestChannel,
	}
	state := &shardState{}

	for _, p := range pairs {
		mockUpdater := new(mockLogUpdater)

		marshaledData, err := json.Marshal(p.pair)
		if err != nil {
			t.Fatalf("Unexpected error marshaling e164 streamPair")
		}

		for _, pair := range p.expectedUpdateInputs {
			mockUpdater.On("update", mock.Anything, mock.Anything, pair.key, pair.value, mock.Anything, pair.preUpdateValue).Return(nil)
		}

		err = updaterFunc(context.Background(), marshaledData, state, mockUpdateHandler, mockUpdater)

		assert.NoError(t, err)
		mockUpdater.AssertNumberOfCalls(t, "update", p.expectedNumUpdates)
		mockUpdater.AssertExpectations(t)
	}
}

var testUpdateE164Pairs = []testCase[e164]{
	// No change
	{
		&streamPair[e164]{
			Prev: &e164{
				Number: validPhoneNumber1,
				ACI:    validAci1,
			},
			Next: &e164{
				Number: validPhoneNumber1,
				ACI:    validAci1,
			},
		},
		0,
		[]expectedUpdateInputs{},
	},
	// Add E164
	{
		&streamPair[e164]{
			Prev: nil,
			Next: &e164{
				Number: validPhoneNumber1,
				ACI:    validAci1,
			},
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.NumberPrefix}, []byte(validPhoneNumber1)...), value: marshalValue(validAci1), preUpdateValue: nil},
		},
	},
	// Delete E164
	{
		&streamPair[e164]{
			Prev: &e164{
				Number: validPhoneNumber1,
				ACI:    validAci1,
			},
			Next: nil,
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.NumberPrefix}, []byte(validPhoneNumber1)...), value: tombstoneBytes, preUpdateValue: marshalValue(validAci1)},
		},
	},
	// Update E164
	{
		&streamPair[e164]{
			Prev: &e164{
				Number: validPhoneNumber1,
				ACI:    validAci1,
			},
			Next: &e164{
				Number: validPhoneNumber1,
				ACI:    validAci2,
			},
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.NumberPrefix}, []byte(validPhoneNumber1)...), value: marshalValue(validAci2), preUpdateValue: nil},
		},
	},
}

func TestUpdateFromE164Stream(t *testing.T) {
	testStreamUpdate[e164](t, testUpdateE164Pairs, updateFromE164Stream)
}

var testUpdateUsernameHashPairs = []testCase[usernameHash]{
	// No change
	{
		&streamPair[usernameHash]{
			Prev: &usernameHash{
				UsernameHash: validUsernameHash1,
				ACI:          validAci1,
			},
			Next: &usernameHash{
				UsernameHash: validUsernameHash1,
				ACI:          validAci1,
			},
		},
		0,
		[]expectedUpdateInputs{},
	},
	// Add username hash
	{
		&streamPair[usernameHash]{
			Prev: nil,
			Next: &usernameHash{
				UsernameHash: validUsernameHash1,
				ACI:          validAci1,
			},
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...), value: marshalValue(validAci1), preUpdateValue: nil},
		},
	},
	// Delete username hash
	{
		&streamPair[usernameHash]{
			Prev: &usernameHash{
				UsernameHash: validUsernameHash1,
				ACI:          validAci1,
			},
			Next: nil,
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...), value: tombstoneBytes, preUpdateValue: marshalValue(validAci1)},
		},
	},
	// Update username hash
	{
		&streamPair[usernameHash]{
			Prev: &usernameHash{
				UsernameHash: validUsernameHash1,
				ACI:          validAci1,
			},
			Next: &usernameHash{
				UsernameHash: validUsernameHash1,
				ACI:          validAci2,
			},
		},
		1,
		[]expectedUpdateInputs{
			{key: append([]byte{shared.UsernameHashPrefix}, validUsernameHash1...), value: marshalValue(validAci2), preUpdateValue: nil},
		},
	},
}

func TestUpdateFromUsernameHashStream(t *testing.T) {
	testStreamUpdate[usernameHash](t, testUpdateUsernameHashPairs, updateFromUsernameStream)
}
