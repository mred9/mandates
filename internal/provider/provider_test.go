package provider_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mred9/mandates/internal/provider"
	"github.com/mred9/mandates/internal/provider/abc"
	"github.com/mred9/mandates/internal/provider/providertest"
	"github.com/mred9/mandates/internal/provider/xyz"
)

var ada = provider.Identity{
	Name:    "Ada Lovelace",
	Phone:   "+44 20 7946 0958",
	Address: provider.Address{StreetAddress: "12 St James's Square", Locality: "London", PostalCode: "SW1Y 4JH", Country: "gb"},
}

var adaLookup = provider.LookupRequest{Phone: "+44 (20) 7946-0958", Name: "Ada Lovelace"}

type vendor struct {
	name string
	fake func(testing.TB, ...provider.Identity) *providertest.Fake
	new  func(provider.VendorConfig, provider.Secrets) (*provider.Client, error)
}

// The resilience tests run against both vendors, so each adapter's wiring
// into the shared client is covered, not just the client.
var vendors = []vendor{{abc.Name, abc.NewFake, abc.New}, {xyz.Name, xyz.NewFake, xyz.New}}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	p     *provider.Client
	fake  *providertest.Fake
	clock *clock
}

// forEachVendor runs fn against each vendor's fake, with millisecond backoff
// and a fake clock for token expiry and breaker cooldown.
func forEachVendor(t *testing.T, cfg provider.VendorConfig, fn func(t *testing.T, e env)) {
	for _, v := range vendors {
		t.Run(v.name, func(t *testing.T) {
			f := v.fake(t, ada)
			c := &clock{t: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
			cfg := cfg
			cfg.BaseURL, cfg.Now = f.URL, c.Now
			if cfg.BackoffBase == 0 {
				cfg.BackoffBase = time.Millisecond
			}
			p, err := v.new(cfg, provider.StaticSecrets{v.name: providertest.Creds})
			if err != nil {
				t.Fatal(err)
			}
			fn(t, env{p, f, c})
		})
	}
}

func lookup(t *testing.T, e env) {
	t.Helper()
	if _, err := e.p.Lookup(context.Background(), adaLookup); err != nil {
		t.Fatalf("lookup: %v", err)
	}
}

func TestLookupMapsVendorAnswer(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		got, err := e.p.Lookup(context.Background(), adaLookup)
		if err != nil {
			t.Fatal(err)
		}
		want := ada
		want.Provider, want.Phone, want.Address.Country = e.p.Name(), "+442079460958", "GB"
		if got != want {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}

		_, err = e.p.Lookup(context.Background(), provider.LookupRequest{Phone: "+15550001111", Name: "Nobody"})
		if !errors.Is(err, provider.ErrNotFound) {
			t.Fatalf("no match: got %v, want ErrNotFound", err)
		}
	})
}

func TestLookupRejectsBadInputWithoutCallingVendor(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		for _, req := range []provider.LookupRequest{
			{Phone: "555-1234", Name: "Ada Lovelace"},
			{Phone: "+442079460958", Name: "  "},
		} {
			if _, err := e.p.Lookup(context.Background(), req); !errors.Is(err, provider.ErrInvalidRequest) {
				t.Errorf("%+v: got %v, want ErrInvalidRequest", req, err)
			}
		}
		if n := e.fake.AuthCalls() + e.fake.IdentityCalls(); n != 0 {
			t.Fatalf("vendor called %d times", n)
		}
	})
}

func TestTokenCachedUntilRefreshWindow(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{RefreshBefore: time.Minute}, func(t *testing.T, e env) {
		for range 3 {
			lookup(t, e)
		}
		e.clock.Advance(time.Hour - time.Minute - time.Second) // TTL 3600s, one second outside the window
		lookup(t, e)
		if n := e.fake.AuthCalls(); n != 1 {
			t.Fatalf("/auth called %d times before the refresh window, want 1", n)
		}
		e.clock.Advance(2 * time.Second)
		lookup(t, e)
		if n := e.fake.AuthCalls(); n != 2 {
			t.Fatalf("/auth called %d times inside the refresh window, want 2", n)
		}
	})
}

func TestTokenWithoutExpiresInLastsFiveMinutes(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		e.fake.SetTokenTTL(0)
		lookup(t, e)
		e.clock.Advance(5*time.Minute - 31*time.Second) // default RefreshBefore is 30s
		lookup(t, e)
		e.clock.Advance(2 * time.Second)
		lookup(t, e)
		if n := e.fake.AuthCalls(); n != 2 {
			t.Fatalf("/auth called %d times, want 2", n)
		}
	})
}

func TestConcurrentLookupsShareOneAuth(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		e.fake.SetAuthDelay(50 * time.Millisecond)
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				if _, err := e.p.Lookup(context.Background(), adaLookup); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if n := e.fake.AuthCalls(); n != 1 {
			t.Fatalf("/auth called %d times, want 1", n)
		}
	})
}

func TestBadCredentialsAreNotRetried(t *testing.T) {
	for _, v := range vendors {
		t.Run(v.name, func(t *testing.T) {
			f := v.fake(t, ada)
			p, err := v.new(provider.VendorConfig{BaseURL: f.URL, BackoffBase: time.Millisecond},
				provider.StaticSecrets{v.name: {Username: providertest.Creds.Username, Password: "wrong"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Lookup(context.Background(), adaLookup); !errors.Is(err, provider.ErrUnauthorized) {
				t.Fatalf("got %v, want ErrUnauthorized", err)
			}
			if n := f.AuthCalls(); n != 1 {
				t.Fatalf("/auth called %d times, want 1", n)
			}
		})
	}
}

func TestStaleTokenIsRefreshedOnce(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		lookup(t, e)
		e.fake.Fail(1, 401, "") // the vendor revoked the cached token
		lookup(t, e)
		if n := e.fake.AuthCalls(); n != 2 {
			t.Fatalf("/auth called %d times, want 2", n)
		}

		e.fake.Fail(2, 401, "")
		if _, err := e.p.Lookup(context.Background(), adaLookup); !errors.Is(err, provider.ErrUnauthorized) {
			t.Fatalf("second 401: got %v, want ErrUnauthorized", err)
		}
		if n := e.fake.AuthCalls(); n != 3 {
			t.Fatalf("/auth called %d times, want 3 (one refresh per lookup)", n)
		}
	})
}

func TestTransientFailuresAreRetried(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		for _, status := range []int{429, 502, 503, 504} {
			before := e.fake.IdentityCalls()
			e.fake.Fail(2, status, "")
			lookup(t, e)
			if n := e.fake.IdentityCalls() - before; n != 3 {
				t.Errorf("%d: /identity called %d times, want 3", status, n)
			}
		}

		e.fake.Fail(10, 503, "")
		before := e.fake.IdentityCalls()
		if _, err := e.p.Lookup(context.Background(), adaLookup); !errors.Is(err, provider.ErrUnavailable) {
			t.Fatalf("exhausted: got %v, want ErrUnavailable", err)
		}
		if n := e.fake.IdentityCalls() - before; n != 3 {
			t.Fatalf("exhausted: /identity called %d times, want MaxAttempts (3)", n)
		}
	})
}

func TestRetryAfterIsHonouredUpToBackoffMax(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{BackoffMax: 80 * time.Millisecond}, func(t *testing.T, e env) {
		lookup(t, e)
		e.fake.Fail(1, 429, "10")
		start := time.Now()
		lookup(t, e)
		// Backoff alone would wait at most BackoffBase (1ms); Retry-After asks for 10s.
		if d := time.Since(start); d < 80*time.Millisecond || d > 2*time.Second {
			t.Fatalf("waited %v, want Retry-After capped at 80ms", d)
		}
	})
}

func TestSlowAttemptsTimeOutAndAreRetried(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{Timeout: 50 * time.Millisecond}, func(t *testing.T, e env) {
		e.fake.SetLatency(time.Second)
		if _, err := e.p.Lookup(context.Background(), adaLookup); !errors.Is(err, provider.ErrUnavailable) {
			t.Fatalf("got %v, want ErrUnavailable", err)
		}
		if n := e.fake.IdentityCalls(); n != 3 {
			t.Fatalf("/identity called %d times, want 3", n)
		}
	})
}

func TestCancelledCallerStopsRetries(t *testing.T) {
	for _, attempts := range []int{1, 3} { // 1: the caller gives up during the last attempt
		forEachVendor(t, provider.VendorConfig{MaxAttempts: attempts}, func(t *testing.T, e env) {
			e.fake.SetLatency(time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := e.p.Lookup(ctx, adaLookup)
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, provider.ErrUnavailable) {
				t.Fatalf("got %v, want the caller's context error", err)
			}
			if n := e.fake.IdentityCalls(); n != 1 {
				t.Fatalf("/identity called %d times, want 1", n)
			}
		})
	}
}

func TestPermanentFailuresAreNotRetried(t *testing.T) {
	forEachVendor(t, provider.VendorConfig{}, func(t *testing.T, e env) {
		for status, want := range map[int]error{
			400: provider.ErrInvalidRequest,
			404: provider.ErrNotFound,
			500: provider.ErrUnavailable,
		} {
			before := e.fake.IdentityCalls()
			e.fake.Fail(1, status, "")
			if _, err := e.p.Lookup(context.Background(), adaLookup); !errors.Is(err, want) {
				t.Errorf("%d: got %v, want %v", status, err, want)
			}
			if n := e.fake.IdentityCalls() - before; n != 1 {
				t.Errorf("%d: /identity called %d times, want 1", status, n)
			}
		}
	})
}

func TestBreakerOpensAndRecovers(t *testing.T) {
	cfg := provider.VendorConfig{MaxAttempts: 1, BreakerThreshold: 2, BreakerCooldown: time.Minute}
	forEachVendor(t, cfg, func(t *testing.T, e env) {
		ctx := context.Background()
		fail := func() {
			t.Helper()
			e.fake.Fail(1, 503, "")
			if _, err := e.p.Lookup(ctx, adaLookup); !errors.Is(err, provider.ErrUnavailable) {
				t.Fatalf("got %v, want ErrUnavailable", err)
			}
		}
		fail()
		if _, err := e.p.Lookup(ctx, provider.LookupRequest{Phone: "+15550001111", Name: "Nobody"}); !errors.Is(err, provider.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
		fail() // the not-found answer reset the count: this is failure 1 of 2
		fail()

		before := e.fake.IdentityCalls()
		if _, err := e.p.Lookup(ctx, adaLookup); !errors.Is(err, provider.ErrCircuitOpen) {
			t.Fatalf("open: got %v, want ErrCircuitOpen", err)
		}
		if e.fake.IdentityCalls() != before {
			t.Fatal("an open breaker called the vendor")
		}

		e.clock.Advance(time.Minute)
		lookup(t, e) // the half-open probe succeeds and closes the breaker
		lookup(t, e)
	})
}

func TestBreakerAllowsOneProbeAtATime(t *testing.T) {
	c := &clock{t: time.Now()}
	b := provider.NewBreaker(1, time.Minute, c.Now)
	b.Record(provider.ErrUnavailable)
	if err := b.Allow(); !errors.Is(err, provider.ErrCircuitOpen) {
		t.Fatalf("got %v, want ErrCircuitOpen", err)
	}
	c.Advance(time.Minute)
	if err := b.Allow(); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := b.Allow(); !errors.Is(err, provider.ErrCircuitOpen) {
		t.Fatalf("second caller during the probe: got %v, want ErrCircuitOpen", err)
	}
	b.Record(provider.ErrUnavailable) // the probe failed: open for another cooldown
	if err := b.Allow(); !errors.Is(err, provider.ErrCircuitOpen) {
		t.Fatalf("after a failed probe: got %v, want ErrCircuitOpen", err)
	}
}

func TestInvalidateKeepsANewerToken(t *testing.T) {
	var fetches int
	cache := provider.NewTokenCache(func(context.Context) (provider.Token, error) {
		fetches++
		return provider.Token{AccessToken: string(rune('a' + fetches)), ExpiresAt: time.Now().Add(time.Hour)}, nil
	}, time.Minute, time.Now)
	ctx := context.Background()
	old, _ := cache.Token(ctx)
	cache.Invalidate(old)
	fresh, _ := cache.Token(ctx)
	cache.Invalidate(old) // a late caller still holding the old token
	if got, _ := cache.Token(ctx); got != fresh || fetches != 2 {
		t.Fatalf("got %q after %d fetches, want %q after 2", got, fetches, fresh)
	}
}

func TestNoSecretsOrPIIInErrorsOrLogs(t *testing.T) {
	big := provider.Identity{Name: strings.Repeat("A", 2<<20), Phone: "+15550002222"}
	for _, v := range vendors {
		t.Run(v.name, func(t *testing.T) {
			f := v.fake(t, ada, big)
			newClient := func(password string) *provider.Client {
				p, err := v.new(provider.VendorConfig{BaseURL: f.URL, BackoffBase: time.Millisecond, BreakerThreshold: 100},
					provider.StaticSecrets{v.name: {Username: providertest.Creds.Username, Password: password}})
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			p := newClient(providertest.Creds.Password)
			ctx := context.Background()
			lookup(t, env{p: p})

			var errs []error
			try := func(p *provider.Client, req provider.LookupRequest) {
				_, err := p.Lookup(ctx, req)
				if err == nil {
					t.Fatalf("%+v: want an error", req)
				}
				errs = append(errs, err)
			}
			try(newClient("wrong-"+providertest.Creds.Password), adaLookup)
			f.Fail(3, 503, "")
			try(p, adaLookup)
			f.Fail(1, 400, "")
			try(p, adaLookup)
			f.Fail(2, 401, "")
			try(p, adaLookup)
			try(p, provider.LookupRequest{Phone: "+15550001111", Name: "Ada Lovelace"})
			try(p, provider.LookupRequest{Phone: "+44 20 7946 095", Name: "Ada Lovelace"})
			try(p, provider.LookupRequest{Phone: big.Phone, Name: "x"}) // answer over the body cap
			if !errors.Is(errs[len(errs)-1], provider.ErrUnavailable) {
				t.Fatalf("oversized answer: got %v, want ErrUnavailable", errs[len(errs)-1])
			}

			var logs bytes.Buffer
			slog.New(slog.NewJSONHandler(&logs, nil)).Info("x",
				"identity", ada, "req", adaLookup, "creds", providertest.Creds,
				"token", provider.Token{AccessToken: f.Tokens()[0]})

			secrets := append([]string{providertest.Creds.Password, "Lovelace", "2079460958", "7946"}, f.Tokens()...)
			for _, s := range secrets {
				for _, err := range errs {
					if strings.Contains(err.Error(), s) {
						t.Errorf("error %q contains %q", err, s)
					}
				}
				if strings.Contains(logs.String(), s) {
					t.Errorf("log %s contains %q", logs.String(), s)
				}
			}
		})
	}
}

func TestBaseURLMustBeHTTPSUnlessLoopback(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://idp.example.com": true,
		"http://127.0.0.1:8080":   true,
		"http://idp.example.com":  false,
		"ftp://idp.example.com":   false,
		"":                        false,
	} {
		_, err := abc.New(provider.VendorConfig{BaseURL: url}, provider.StaticSecrets{})
		if (err == nil) != ok {
			t.Errorf("%q: got %v, want ok=%v", url, err, ok)
		}
	}
}
