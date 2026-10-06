// Package providertest is an httptest stand-in for an identity provider: the
// /auth and /identity protocol, token expiry and injectable failures. Each
// vendor's fake supplies only its identity response body.
package providertest

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mred9/mandates/internal/profile"
	"github.com/mred9/mandates/internal/provider"
)

// Creds are the credentials every fake accepts.
var Creds = provider.Credentials{Username: "svc-mandates", Password: "fake-vendor-password"}

// Writer writes the vendor's /identity answer; id is nil when no one matches.
type Writer func(w http.ResponseWriter, id *provider.Identity)

type Fake struct {
	*httptest.Server
	write Writer

	mu            sync.Mutex
	people        map[string]provider.Identity // by E.164 phone
	tokenTTL      int                          // expires_in seconds; 0 omits the field
	tokens        []string
	fails         []fail
	latency       time.Duration
	authDelay     time.Duration
	authCalls     int
	identityCalls int
}

type fail struct {
	status     int
	retryAfter string
}

func New(t testing.TB, write Writer, people ...provider.Identity) *Fake {
	f := &Fake{write: write, people: map[string]provider.Identity{}, tokenTTL: 3600}
	for _, p := range people {
		phone, err := profile.NormalizePhone(p.Phone)
		if err != nil {
			t.Fatal(err)
		}
		f.people[phone] = p
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth", f.auth)
	mux.HandleFunc("POST /identity", f.identity)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// SetTokenTTL sets expires_in on issued tokens; 0 omits it.
func (f *Fake) SetTokenTTL(seconds int) { f.mu.Lock(); f.tokenTTL = seconds; f.mu.Unlock() }

// Fail makes the next n /identity calls answer status, with Retry-After when set.
func (f *Fake) Fail(n, status int, retryAfter string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for range n {
		f.fails = append(f.fails, fail{status, retryAfter})
	}
}

// SetLatency delays every /identity answer.
func (f *Fake) SetLatency(d time.Duration) { f.mu.Lock(); f.latency = d; f.mu.Unlock() }

// SetAuthDelay delays every /auth answer.
func (f *Fake) SetAuthDelay(d time.Duration) { f.mu.Lock(); f.authDelay = d; f.mu.Unlock() }

func (f *Fake) AuthCalls() int     { f.mu.Lock(); defer f.mu.Unlock(); return f.authCalls }
func (f *Fake) IdentityCalls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.identityCalls }

// Tokens returns every access token issued so far.
func (f *Fake) Tokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokens...)
}

func (f *Fake) auth(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authCalls++
	delay, ttl := f.authDelay, f.tokenTTL
	f.mu.Unlock()
	if !sleep(r, delay) {
		return
	}
	var c struct{ Username, Password string }
	if json.NewDecoder(r.Body).Decode(&c) != nil || c.Username != Creds.Username || c.Password != Creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tok := rand.Text()
	f.mu.Lock()
	f.tokens = append(f.tokens, tok)
	f.mu.Unlock()
	resp := map[string]any{"access_token": tok}
	if ttl > 0 {
		resp["expires_in"] = ttl
	}
	json.NewEncoder(w).Encode(resp)
}

func (f *Fake) identity(w http.ResponseWriter, r *http.Request) {
	// Read the body first: only then does the server notice a client that gives up during the latency.
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.identityCalls++
	latency := f.latency
	var injected *fail
	if len(f.fails) > 0 {
		injected, f.fails = &f.fails[0], f.fails[1:]
	}
	f.mu.Unlock()
	if !sleep(r, latency) {
		return
	}
	if injected != nil {
		if injected.retryAfter != "" {
			w.Header().Set("Retry-After", injected.retryAfter)
		}
		w.WriteHeader(injected.status)
		return
	}
	if !f.validToken(r.Header.Get("Authorization")) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct{ Phone, Name string }
	if json.Unmarshal(body, &req) != nil || req.Phone == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	p, ok := f.people[req.Phone]
	f.mu.Unlock()
	if !ok {
		f.write(w, nil)
		return
	}
	f.write(w, &p)
}

func (f *Fake) validToken(header string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if header == "Bearer "+t {
			return true
		}
	}
	return false
}

// sleep waits d, or returns false if the client gave up first.
func sleep(r *http.Request, d time.Duration) bool {
	if d == 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-r.Context().Done():
		return false
	}
}
