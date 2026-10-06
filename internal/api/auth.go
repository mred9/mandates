package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
	"sync"
	"time"
)

const ScopeProfilesRead = "profiles:read"

type Principal struct {
	ClientID string
	Scopes   []string
}

// TokenVerifier turns a bearer token into a Principal, or ErrUnauthenticated.
// TODO: production verifies JWTs from the authorization server (JWKS, iss,
// aud, exp, scope) or calls RFC 7662 introspection.
type TokenVerifier interface {
	Verify(ctx context.Context, bearer string) (Principal, error)
}

// DevTokens is an in-memory issuer of opaque tokens. Dev and tests only.
// Tokens are stored by SHA-256, so the lookup doesn't compare secrets
// byte by byte and a memory dump doesn't hold usable tokens.
type DevTokens struct {
	mu     sync.Mutex
	tokens map[[32]byte]devToken
}

type devToken struct {
	p       Principal
	expires time.Time
}

func NewDevTokens() *DevTokens { return &DevTokens{tokens: map[[32]byte]devToken{}} }

func (d *DevTokens) Mint(clientID string, scopes []string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokens[sha256.Sum256([]byte(tok))] = devToken{Principal{clientID, scopes}, time.Now().Add(ttl)}
	return tok, nil
}

func (d *DevTokens) Verify(_ context.Context, bearer string) (Principal, error) {
	d.mu.Lock()
	t, ok := d.tokens[sha256.Sum256([]byte(bearer))]
	d.mu.Unlock()
	if !ok || !time.Now().Before(t.expires) {
		return Principal{}, ErrUnauthenticated
	}
	return t.p, nil
}

// bearer extracts the token from an Authorization header.
func bearer(header string) (string, bool) {
	scheme, tok, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}

func (p Principal) has(scope string) bool { return slices.Contains(p.Scopes, scope) }
