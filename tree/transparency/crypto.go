//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package transparency

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/signalapp/keytransparency/crypto/commitments"
	edvrf "github.com/signalapp/keytransparency/crypto/vrf/ed25519"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/transparency/pb"
)

// computeOpening returns the opening for the commitment stored at position
// `pos` in the transparency tree.
func computeOpening(key []byte, pos uint64) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	data := make([]byte, block.BlockSize())
	binary.BigEndian.PutUint64(data[len(data)-8:], pos)
	block.Encrypt(data, data)
	return data
}

// fakeCommitment returns the commitment to use at a given position in the
// transparency log for fake updates.
func fakeCommitment(key []byte, pos uint64) ([]byte, error) {
	commitment, err := commitments.Commit(nil, nil, computeOpening(key, pos))
	if err != nil {
		return nil, err
	}
	return commitment, nil
}

// leafHash returns the hash of the leaf of the transparency tree.
func leafHash(prefixRoot, commitment []byte) []byte {
	s := sha256.New()
	s.Write(prefixRoot)
	s.Write(commitment)
	return s.Sum(nil)
}

// signNewHead returns a new signed transparency tree head.
func signNewHead(config *PrivateConfig, treeSize uint64, root []byte) (*db.TransparencyTreeHead, error) {
	tbs := &treeHeadTbs{
		TreeSize:  treeSize,
		Timestamp: time.Now().UnixMilli(),
		Root:      root,
	}

	keys := config.AuditorKeys
	if len(keys) == 0 {
		// Create a placeholder mapping for the auditor key since it won't be marshaled anyway
		keys = map[string]ed25519.PublicKey{"": nil}
	}

	var signatures []*db.Signature
	for _, key := range keys {
		raw, err := tbs.Marshal(config.Public(), key)
		if err != nil {
			return nil, err
		}
		sig, err := config.SigKey.Sign(nil, raw, crypto.Hash(0))
		if err != nil {
			return nil, err
		}
		signature := &db.Signature{Signature: sig, AuditorPublicKey: key}
		signatures = append(signatures, signature)
	}

	return &db.TransparencyTreeHead{
		TreeSize:   treeSize,
		Timestamp:  tbs.Timestamp,
		Signatures: signatures,
	}, nil
}

// SignNewAuditorHead returns a new signed transparency tree head from an
// auditor. It is only used for testing purposes.
func SignNewAuditorHead(sigKey ed25519.PrivateKey, config *PublicConfig, treeSize uint64, root []byte, auditorName string) (*db.AuditorTransparencyTreeHead, []byte, error) {
	tbs := &treeHeadTbs{
		TreeSize:  treeSize,
		Timestamp: time.Now().UnixMilli(),
		Root:      root,
	}
	auditorPublicKey := config.AuditorKeys[auditorName]
	raw, err := tbs.Marshal(config, auditorPublicKey)
	if err != nil {
		return nil, nil, err
	}
	sig, err := sigKey.Sign(nil, raw, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return &db.AuditorTransparencyTreeHead{
		TreeSize:  treeSize,
		Timestamp: tbs.Timestamp,
		Signature: sig,
	}, raw, nil
}

// verifyTreeHead checks the signature on the provided transparency tree head.
func verifyTreeHead(config *PublicConfig, head *pb.TreeHead, root []byte) error {
	tbs := &treeHeadTbs{
		TreeSize:  head.TreeSize,
		Timestamp: head.Timestamp,
		Root:      root,
	}

	if len(head.Signatures) == 0 {
		return errors.New("expected at least one key transparency service signature")
	}

	for _, signature := range head.Signatures {
		if config.Mode == ThirdPartyAuditing {
			err := verifyAuditorPublicKey(config.AuditorKeys, signature.AuditorPublicKey)
			if err != nil {
				return err
			}
		}
		raw, err := tbs.Marshal(config, signature.AuditorPublicKey)
		if err != nil {
			return err
		} else if ok := ed25519.Verify(config.SigKey, raw, signature.Signature); !ok {
			return errors.New("failed to verify tree head signature")
		}
	}

	return nil
}

// verifyAuditorPublicKey checks that the provided public key exists in the map of known auditor public keys
// and returns an error if not
func verifyAuditorPublicKey(configAuditorMap map[string]ed25519.PublicKey, auditorPublicKey []byte) error {
	for _, knownPublicKey := range configAuditorMap {
		if bytes.Equal(knownPublicKey, auditorPublicKey) {
			return nil
		}
	}
	return errors.New("provided auditor public key does not match set of known auditor public keys")
}

func verifyAuditorTreeHead(config *PublicConfig, head *pb.FullAuditorTreeHead, root []byte, auditorPublicKey ed25519.PublicKey) error {
	err := verifyAuditorPublicKey(config.AuditorKeys, auditorPublicKey)
	if err != nil {
		return err
	}
	var auditorRoot []byte
	if head.RootValue == nil {
		auditorRoot = root
	} else {
		auditorRoot = head.RootValue
	}
	tbs := &treeHeadTbs{
		TreeSize:  head.TreeHead.TreeSize,
		Timestamp: head.TreeHead.Timestamp,
		Root:      auditorRoot,
	}
	raw, err := tbs.Marshal(config, auditorPublicKey)
	if err != nil {
		return err
	} else if ok := ed25519.Verify(auditorPublicKey, raw, head.TreeHead.Signature); !ok {
		return &ErrAuditorSignatureVerificationFailed{
			dataToBeSigned:           raw,
			auditorPublicKey:         auditorPublicKey,
			auditorProvidedSignature: head.TreeHead.Signature,
		}
	}
	return nil
}

func marshalUpdateValue(uv *pb.UpdateValue) ([]byte, error) {
	buf := &bytes.Buffer{}

	if len(uv.Value) >= 1<<32 {
		return nil, errors.New("value is too long to be encoded")
	}
	binary.Write(buf, binary.BigEndian, uint32(len(uv.Value)))
	buf.Write(uv.Value)

	return buf.Bytes(), nil
}

func unmarshalUpdateValue(raw []byte) (*pb.UpdateValue, error) {
	buf := bytes.NewBuffer(raw)

	var valLen uint32
	if err := binary.Read(buf, binary.BigEndian, &valLen); err != nil {
		return nil, err
	} else if int(valLen) != buf.Len() {
		return nil, errors.New("failed to decode update value")
	}

	return &pb.UpdateValue{Value: buf.Bytes()}, nil
}

type treeHeadTbs struct {
	TreeSize  uint64
	Timestamp int64
	Root      []byte
}

// Marshal a treeHeadTbs structures using the given auditor's public key
func (tbs *treeHeadTbs) Marshal(config *PublicConfig, auditorKey []byte) ([]byte, error) {
	buf := &bytes.Buffer{}

	buf.Write([]byte{0x00, 0x00})        // Ciphersuite
	buf.Write([]byte{byte(config.Mode)}) // Deployment mode

	// Signature public key
	if len(config.SigKey) >= 1<<16 {
		return nil, errors.New("signature key is too long to be encoded")
	}
	binary.Write(buf, binary.BigEndian, uint16(len(config.SigKey)))
	buf.Write(config.SigKey)

	// VRF public key
	vrfBytes := config.VrfKey.(*edvrf.PublicKey).Bytes()
	if len(vrfBytes) >= 1<<16 {
		return nil, errors.New("vrf key is too long to be encoded")
	}
	binary.Write(buf, binary.BigEndian, uint16(len(vrfBytes)))
	buf.Write(vrfBytes)

	// Third-party auditor public key.
	if config.Mode == ThirdPartyAuditing {
		if len(auditorKey) >= 1<<16 {
			return nil, errors.New("auditor public key is too long to be encoded")
		}
		binary.Write(buf, binary.BigEndian, uint16(len(auditorKey)))
		buf.Write(auditorKey)
	}

	binary.Write(buf, binary.BigEndian, tbs.TreeSize)  // Tree size
	binary.Write(buf, binary.BigEndian, tbs.Timestamp) // Timestamp

	// Root hash
	if len(tbs.Root) != 32 {
		return nil, errors.New("root is wrong length")
	}
	buf.Write(tbs.Root)

	return buf.Bytes(), nil
}
