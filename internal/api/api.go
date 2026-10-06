// Package api serves profile reads over HTTP: bearer-token auth with scopes,
// per-client rate limiting, an audit event for every PII read, and logs that
// never carry PII.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mred9/mandates/internal/profile"
)

// Profiles is the part of profile.Repository the API reads through.
type Profiles interface {
	Get(ctx context.Context, id string) (profile.Profile, error)
	Search(ctx context.Context, phone, after string, limit int) ([]profile.Profile, error)
}

type Config struct {
	Profiles Profiles
	Tokens   TokenVerifier
	Auditor  Auditor
	Logger   *slog.Logger
	Rate     rate.Limit // requests per second per client
	Burst    int
}

// MaxBodyBytes bounds every request body.
const MaxBodyBytes = 16 << 10

type api struct {
	cfg     Config
	limiter *limiter
}

// New returns the handler. Middleware, outer to inner: request ID, access log,
// recover (inside the log, so a panic's 500 is logged), then per route: auth
// and scope, rate limit, handler.
func New(cfg Config) http.Handler {
	a := &api{cfg: cfg, limiter: &limiter{r: cfg.Rate, b: cfg.Burst, m: map[string]*rate.Limiter{}}}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/profiles/{id}", a.protect(ScopeProfilesRead, a.getProfile))
	mux.Handle("POST /v1/profiles/search", a.protect(ScopeProfilesRead, a.searchProfiles))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { a.fail(w, r, errNoRoute) })
	return a.withRequestID(a.accessLog(a.recover(mux)))
}

func (a *api) fail(w http.ResponseWriter, r *http.Request, err error) {
	writeError(w, r, a.cfg.Logger, err)
}

// reqState travels in the context; inner middleware fills in the client.
type reqState struct{ id, clientID string }

type ctxKey struct{}

func state(ctx context.Context) *reqState {
	if s, ok := ctx.Value(ctxKey{}).(*reqState); ok {
		return s
	}
	return &reqState{}
}

func requestID(ctx context.Context) string { return state(ctx).id }

// validRequestID keeps caller-supplied IDs safe to log.
var validRequestID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (a *api) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID.MatchString(id) {
			b := make([]byte, 16)
			rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store") // responses carry PII
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &reqState{id: id})))
	})
}

func (a *api) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				a.fail(w, r, fmt.Errorf("panic: %v", v))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// accessLog records the route pattern, never the raw path (it can hold an
// ID) or the query string or body.
func (a *api) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, sw := time.Now(), &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s := state(r.Context())
		a.cfg.Logger.InfoContext(r.Context(), "request", "method", r.Method, "route", r.Pattern,
			"status", sw.status, "duration", time.Since(start), "request_id", s.id, "client_id", s.clientID)
	})
}

// protect authenticates, checks scope and rate-limits before running h.
func (a *api) protect(scope string, h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := a.authorize(w, r, scope)
		if err == nil {
			err = h(w, r)
		}
		if err != nil {
			a.fail(w, r, err)
		}
	})
}

func (a *api) authorize(w http.ResponseWriter, r *http.Request, scope string) error {
	tok, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		return ErrUnauthenticated
	}
	p, err := a.cfg.Tokens.Verify(r.Context(), tok)
	if err != nil {
		return ErrUnauthenticated
	}
	state(r.Context()).clientID = p.ClientID
	if !p.has(scope) {
		return ErrForbidden
	}
	if wait := a.limiter.wait(p.ClientID); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		return ErrRateLimited
	}
	return nil
}

// limiter is a token bucket per client. Keys are authenticated client IDs,
// so the map is bounded by the number of registered clients and needs no eviction.
type limiter struct {
	mu sync.Mutex
	r  rate.Limit
	b  int
	m  map[string]*rate.Limiter
}

// wait takes a token and returns 0, or returns how long until one is free.
func (l *limiter) wait(client string) time.Duration {
	l.mu.Lock()
	lim, ok := l.m[client]
	if !ok {
		lim = rate.NewLimiter(l.r, l.b)
		l.m[client] = lim
	}
	l.mu.Unlock()
	res := lim.Reserve()
	if !res.OK() {
		return time.Second
	}
	d := res.Delay()
	if d > 0 {
		res.Cancel()
	}
	return d
}
