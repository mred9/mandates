// Package credential models login credentials. No plaintext secret is ever
// stored: passwords are argon2id hashes, passkeys are public material only, and
// TOTP seeds are envelope-encrypted (they must be recoverable to verify a code).
package credential

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	ErrInvalid  = errors.New("credential: invalid")
	ErrConflict = errors.New("credential: conflict")
)

type Method string

const (
	MethodPassword Method = "password"
	MethodPasskey  Method = "passkey"
	MethodTOTP     Method = "totp"
)

// Credential mirrors the user_credentials row. Only the fields for Method are set.
type Credential struct {
	ID       string
	UserID   string // profile ID
	Username string
	Method   Method

	PasswordHash string // argon2id PHC string

	PasskeyID        []byte // WebAuthn credential ID
	PasskeyPublicKey []byte // COSE public key

	TOTPWrappedDEK []byte
	TOTPSecret     []byte // ciphertext under the DEK

	CreatedAt time.Time
}

// LogValue keeps hashes and secret material out of logs.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", c.ID), slog.String("method", string(c.Method)))
}

// Store is the CredentialStore. It sits on its own table so it can be granted
// to a different database role than profiles.
type Store interface {
	Create(ctx context.Context, c Credential) error
	FindByUsername(ctx context.Context, username string, m Method) ([]Credential, error)
}

// Validate checks that exactly the payload for c.Method is present.
// The database enforces the same rule with a CHECK constraint.
func (c Credential) Validate() error {
	if c.ID == "" || c.UserID == "" || c.Username == "" {
		return fmt.Errorf("%w: id, user and username are required", ErrInvalid)
	}
	password := c.PasswordHash != ""
	passkey := len(c.PasskeyID) > 0 || len(c.PasskeyPublicKey) > 0
	totp := len(c.TOTPWrappedDEK) > 0 || len(c.TOTPSecret) > 0

	var ok bool
	switch c.Method {
	case MethodPassword:
		ok = password && !passkey && !totp
	case MethodPasskey:
		ok = len(c.PasskeyID) > 0 && len(c.PasskeyPublicKey) > 0 && !password && !totp
	case MethodTOTP:
		ok = len(c.TOTPWrappedDEK) > 0 && len(c.TOTPSecret) > 0 && !password && !passkey
	}
	if !ok {
		return fmt.Errorf("%w: payload does not match method %q", ErrInvalid, c.Method)
	}
	return nil
}
