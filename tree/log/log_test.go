//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package log

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"slices"
	"testing"

	"github.com/signalapp/keytransparency/db"
)

func assert(ok bool) {
	if !ok {
		panic("Assertion failed.")
	}
}

func random() []byte {
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func TestInclusionProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTransparencyStore().LogStore())
	calc := newSimpleRootCalculator()
	var (
		nodes [][]byte
		roots [][]byte
	)

	checkTree := func(entry, treeSize uint64) {
		value, proof, err := tree.Get(entry, treeSize)
		if err != nil {
			t.Fatal(err)
		}
		assert(bytes.Equal(value, nodes[entry]))
		if err := VerifyInclusionProof(entry, treeSize, value, proof, roots[treeSize-1]); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 2000; i++ {
		leaf := random()
		nodes = append(nodes, leaf)

		// Append to the tree.
		root, err := tree.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		calc.Add(leaf)
		if calculated, err := calc.Root(); err != nil {
			t.Fatal(err)
		} else {
			assert(bytes.Equal(root, calculated))
		}

		// Do inclusion proofs for a few random entries.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			x := mrand.Intn(n)
			checkTree(uint64(x), uint64(n))

			m := mrand.Intn(int(n-1)) + 1
			x = mrand.Intn(m)
			checkTree(uint64(x), uint64(m))
		}
	}
}

func TestBatchInclusionProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTransparencyStore().LogStore())
	var (
		leaves [][]byte
		root   []byte
		err    error
	)
	for i := 0; i < 2000; i++ {
		leaf := random()
		leaves = append(leaves, leaf)

		root, err = tree.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
	}

	dedup := make(map[uint64]struct{})
	for i := 0; i < 10; i++ {
		dedup[uint64(mrand.Intn(2000))] = struct{}{}
	}
	entries := make([]uint64, 0)
	for id := range dedup {
		entries = append(entries, id)
	}
	slices.Sort(entries)

	values := make([][]byte, 0)
	for _, id := range entries {
		values = append(values, leaves[id])
	}

	proof, err := tree.GetBatchProof(entries, 2000)
	if err != nil {
		t.Fatal(err)
	} else if err := VerifyBatchProof(entries, 2000, values, proof, root); err != nil {
		t.Fatal(err)
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree(db.NewMemoryTransparencyStore().LogStore())

	var roots [][]byte
	for i := 0; i < 2000; i++ {
		leaf := random()

		// Append to the tree.
		root, err := tree.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, dup(root))
		n := i + 1

		// Do consistency proofs for a few random revisions.
		if n < 5 {
			continue
		}
		for j := 0; j < 5; j++ {
			m := mrand.Intn(n-1) + 1
			proof, err := tree.GetConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyConsistencyProof(uint64(m), uint64(n), proof, roots[m-1], roots[n-1])
			if err != nil {
				t.Fatal(err)
			}

			if m > 1 {
				p := mrand.Intn(m-1) + 1
				proof, err := tree.GetConsistencyProof(uint64(p), uint64(m))
				if err != nil {
					t.Fatal(err)
				}
				err = VerifyConsistencyProof(uint64(p), uint64(m), proof, roots[p-1], roots[m-1])
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestConsistencyProof_EmptyOrSameSizeTrees(t *testing.T) {
	tree := NewTree(db.NewMemoryTransparencyStore().LogStore())

	_, err := tree.GetConsistencyProof(0, 0)
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = tree.GetConsistencyProof(0, 1)
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = tree.GetConsistencyProof(1, 0)
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = tree.GetConsistencyProof(1, 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBatchAppend(t *testing.T) {
	leaves := make([][]byte, 100)
	for i := range leaves {
		leaves[i] = random()
	}

	// Add leaves to tree in batches.
	tree1 := NewTree(db.NewMemoryTransparencyStore().LogStore())
	_, err := tree1.BatchAppend(0, leaves[:50])
	if err != nil {
		t.Fatal(err)
	}
	root1, err := tree1.BatchAppend(50, leaves[50:])
	if err != nil {
		t.Fatal(err)
	}

	// Add leaves to tree one-by-one.
	tree2 := NewTree(db.NewMemoryTransparencyStore().LogStore())
	var root2 []byte
	for i, leaf := range leaves {
		root2, err = tree2.Append(uint64(i), leaf)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Check that roots are the same.
	if !bytes.Equal(root1, root2) {
		t.Fatal("log roots were not equal")
	}
}

func BenchmarkAppend(b *testing.B) {
	tree := NewTree(db.NewMemoryTransparencyStore().LogStore())
	for i := 0; i < 100; i++ {
		_, err := tree.Append(uint64(i), random())
		if err != nil {
			b.Fatal(err)
		}
	}
	leaves := make([][]byte, b.N)
	for i := range leaves {
		leaves[i] = random()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tree.Append(100+uint64(i), leaves[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBatchAppend(b *testing.B) {
	const batchSize = 10

	tree := NewTree(db.NewMemoryTransparencyStore().LogStore())
	for i := 0; i < 100; i++ {
		_, err := tree.Append(uint64(i), random())
		if err != nil {
			b.Fatal(err)
		}
	}
	leaves := make([][]byte, batchSize*b.N)
	for i := range leaves {
		leaves[i] = random()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := batchSize * i
		end := batchSize * (i + 1)
		_, err := tree.BatchAppend(100+uint64(start), leaves[start:end])
		if err != nil {
			b.Fatal(err)
		}
	}
}
