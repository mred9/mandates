// Package crypto provides envelope encryption for PII at rest and an HMAC
// blind index so encrypted fields can still be matched exactly.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// ErrDecrypt covers every decryption failure. Callers learn nothing about why.
var ErrDecrypt = errors.New("crypto: decrypt failed")

// Envelope issues per-record data encryption keys (DEKs) wrapped by a
// key-encryption key (KEK) that never leaves the key service.
type Envelope interface {
	// GenerateDataKey returns a fresh 256-bit DEK and the same key wrapped by the KEK.
	GenerateDataKey(ctx context.Context) (plaintext, wrapped []byte, err error)
	// DecryptDataKey unwraps a DEK produced by GenerateDataKey.
	DecryptDataKey(ctx context.Context, wrapped []byte) ([]byte, error)
}

// LocalKeyEnvelope holds the KEK in process memory. Dev and tests only.
type LocalKeyEnvelope struct{ kek []byte }

func NewLocalKeyEnvelope(kek []byte) (*LocalKeyEnvelope, error) {
	if len(kek) != 32 {
		return nil, errors.New("crypto: KEK must be 32 bytes")
	}
	return &LocalKeyEnvelope{kek: kek}, nil
}

func (e *LocalKeyEnvelope) GenerateDataKey(_ context.Context) ([]byte, []byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	wrapped, err := Seal(e.kek, dek, []byte("dek"))
	if err != nil {
		return nil, nil, err
	}
	return dek, wrapped, nil
}

func (e *LocalKeyEnvelope) DecryptDataKey(_ context.Context, wrapped []byte) ([]byte, error) {
	return Open(e.kek, wrapped, []byte("dek"))
}

// VaultTransitEnvelope is a stub.
// TODO: call Vault transit's datakey/plaintext/<key> to generate and
// decrypt/<key> to unwrap, so the KEK lives only in Vault and is rotated there.
type VaultTransitEnvelope struct{ Addr, KeyName string }

var errNotImplemented = errors.New("crypto: vault transit not implemented")

func (VaultTransitEnvelope) GenerateDataKey(context.Context) ([]byte, []byte, error) {
	return nil, nil, errNotImplemented
}

func (VaultTransitEnvelope) DecryptDataKey(context.Context, []byte) ([]byte, error) {
	return nil, errNotImplemented
}

// Seal encrypts with AES-256-GCM and returns nonce||ciphertext. aad binds the
// ciphertext to its context (row ID and column) so it cannot be moved elsewhere.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal.
func Open(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// BlindIndex is HMAC-SHA256 under a key separate from the KEK. Callers
// normalise the value first; equal inputs give equal indexes.
type BlindIndex struct{ key []byte }

// NewBlindIndex rejects short keys: a blank key from config would silently
// produce an index anyone could brute-force.
func NewBlindIndex(key []byte) (*BlindIndex, error) {
	if len(key) < 32 {
		return nil, errors.New("crypto: blind index key must be at least 32 bytes")
	}
	return &BlindIndex{key: key}, nil
}

func (b *BlindIndex) Sum(value string) []byte {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(value))
	return m.Sum(nil)
}
