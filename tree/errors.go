package tree

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

var (
	ErrDuplicateUpdate = errors.New("duplicate update")
	ErrOutOfRange      = errors.New("querying past end of log")
	ErrNotFound        = errors.New("not found")
	ErrEmptyTree       = errors.New("empty tree")
)

// ErrInvalidTreeConfiguration indicates that the server is not configured correctly to handle this request.
type ErrInvalidTreeConfiguration struct {
	Field   string
	Message string
}

func (e *ErrInvalidTreeConfiguration) Error() string {
	return fmt.Sprintf("invalid configuration for %s: %s", e.Field, e.Message)
}

type ErrAuditorSignatureVerificationFailed struct {
	DataToBeSigned           []byte
	AuditorPublicKey         ed25519.PublicKey
	AuditorProvidedSignature []byte
}

func (e *ErrAuditorSignatureVerificationFailed) Error() string {
	return fmt.Sprintf("auditor signature verification failed.\ndataToBeSigned: %x\n, auditorPublicKey:%x\n, auditorSig: %x",
		e.DataToBeSigned, e.AuditorPublicKey, e.AuditorProvidedSignature)
}
