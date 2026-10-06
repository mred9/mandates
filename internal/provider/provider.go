// Package provider looks up identities at third-party identity providers.
// Client does the vendor-independent work (authentication, token caching,
// retries, circuit breaking); the abc and xyz packages only encode a request
// and decode their vendor's answer.
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	ErrNotFound       = errors.New("provider: not found")
	ErrInvalidRequest = errors.New("provider: invalid request")
	ErrUnauthorized   = errors.New("provider: unauthorized")
	ErrUnavailable    = errors.New("provider: unavailable")
	ErrCircuitOpen    = errors.New("provider: circuit open")
)

type Address struct {
	StreetAddress, Locality, Region, PostalCode, Country string
}

type Identity struct {
	Provider string
	Name     string
	Phone    string // E.164
	Address  Address
}

// LogValue keeps vendor PII out of logs even when an Identity is logged by mistake.
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("provider", i.Provider), slog.String("pii", "[REDACTED]"))
}

type LookupRequest struct{ Phone, Name string }

func (LookupRequest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type IdentityProvider interface {
	Name() string
	Lookup(ctx context.Context, req LookupRequest) (Identity, error)
}

type Credentials struct{ Username, Password string }

func (Credentials) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type Secrets interface {
	VendorCredentials(ctx context.Context, vendor string) (Credentials, error)
}

// StaticSecrets holds credentials in memory, keyed by secret name. Dev and tests only.
type StaticSecrets map[string]Credentials

func (s StaticSecrets) VendorCredentials(_ context.Context, vendor string) (Credentials, error) {
	c, ok := s[vendor]
	if !ok {
		return Credentials{}, fmt.Errorf("provider: no credentials for %q", vendor)
	}
	return c, nil
}

// VaultSecrets reads vendor credentials from Vault.
// TODO: read kv-v2 secret/data/idp/<vendor> with the service's Vault token
// (Kubernetes auth), and cache it for the secret's lease so rotation is picked up.
type VaultSecrets struct{ Addr, Mount string }

func (VaultSecrets) VendorCredentials(context.Context, string) (Credentials, error) {
	return Credentials{}, errors.New("provider: VaultSecrets is not implemented")
}

// VendorConfig tunes one vendor's client. Zero fields take the defaults below.
type VendorConfig struct {
	BaseURL          string        // https, or http on a loopback host (tests)
	Timeout          time.Duration // per attempt (its /auth, /identity and any re-auth); default 5s
	MaxAttempts      int           // default 3
	BackoffBase      time.Duration // default 100ms
	BackoffMax       time.Duration // also caps Retry-After; default 2s
	BreakerThreshold int           // consecutive failed lookups that open the breaker; default 5
	BreakerCooldown  time.Duration // default 30s
	RefreshBefore    time.Duration // refresh a token this long before expiry; default 30s
	DefaultTokenTTL  time.Duration // when /auth omits expires_in; default 5m
	SecretName       string        // default: the vendor name
	Now              func() time.Time
}

func (c VendorConfig) withDefaults(vendor string) VendorConfig {
	set := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	set(&c.Timeout, 5*time.Second)
	set(&c.BackoffBase, 100*time.Millisecond)
	set(&c.BackoffMax, 2*time.Second)
	set(&c.BreakerCooldown, 30*time.Second)
	set(&c.RefreshBefore, 30*time.Second)
	set(&c.DefaultTokenTTL, 5*time.Minute)
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 3
	}
	if c.BreakerThreshold == 0 {
		c.BreakerThreshold = 5
	}
	if c.SecretName == "" {
		c.SecretName = vendor
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}
