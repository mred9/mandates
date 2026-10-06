package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mred9/mandates/internal/profile"
)

// maxBody caps how much of a vendor's answer is read.
const maxBody = 1 << 20

type (
	// Encoder builds the vendor's /identity request body.
	Encoder func(LookupRequest) any
	// Decoder maps a 200 answer to an Identity, or returns ErrNotFound.
	Decoder func(body []byte) (Identity, error)
)

// Client is an IdentityProvider for one vendor. It authenticates, caches the
// token, retries and circuit-breaks; the vendor package supplies enc and dec.
type Client struct {
	vendor  string
	cfg     VendorConfig
	secrets Secrets
	enc     Encoder
	dec     Decoder
	http    *http.Client
	tokens  *TokenCache
	breaker *Breaker
}

func New(vendor string, cfg VendorConfig, s Secrets, enc Encoder, dec Decoder) (*Client, error) {
	cfg = cfg.withDefaults(vendor)
	if err := checkBaseURL(cfg.BaseURL); err != nil {
		return nil, err
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	c := &Client{
		vendor: vendor, cfg: cfg, secrets: s, enc: enc, dec: dec,
		// No redirects: credentials and tokens go only to the configured host.
		http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		breaker: NewBreaker(cfg.BreakerThreshold, cfg.BreakerCooldown, cfg.Now),
	}
	c.tokens = NewTokenCache(c.authenticate, cfg.RefreshBefore, cfg.Now)
	return c, nil
}

// checkBaseURL requires https, so credentials never cross the network in clear.
// Plain http is allowed only to a loopback host, for the test fakes.
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("provider: invalid base URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("provider: base URL must be https")
}

func (c *Client) Name() string { return c.vendor }

// Lookup errors carry the vendor, operation and status, never the request,
// the answer or credentials.
func (c *Client) Lookup(ctx context.Context, req LookupRequest) (Identity, error) {
	phone, err := profile.NormalizePhone(req.Phone)
	if err != nil || strings.TrimSpace(req.Name) == "" {
		return Identity{}, fmt.Errorf("provider %s: %w: phone must be E.164 and name non-empty", c.vendor, ErrInvalidRequest)
	}
	req.Phone = phone

	var id Identity
	refreshed := false // one re-auth per lookup, across retry attempts
	err = Do(ctx, c.cfg, c.breaker, func(ctx context.Context) error {
		body, err := c.identity(ctx, c.enc(req), &refreshed)
		if err != nil {
			return err
		}
		if id, err = c.dec(body); errors.Is(err, ErrNotFound) {
			return err
		} else if err != nil {
			return fmt.Errorf("%w: malformed identity response", ErrUnavailable) // not err: it may quote the body
		}
		return c.normalise(&id)
	})
	if err != nil {
		return Identity{}, fmt.Errorf("provider %s: lookup: %w", c.vendor, err)
	}
	return id, nil
}

// identity posts to /identity. A 401 means the cached token went stale: drop
// it and try once more with a fresh one.
func (c *Client) identity(ctx context.Context, payload any, refreshed *bool) ([]byte, error) {
	for {
		tok, err := c.tokens.Token(ctx)
		if err != nil {
			return nil, err
		}
		status, h, body, err := c.post(ctx, "/identity", tok, payload)
		if err != nil {
			return nil, err
		}
		if status == http.StatusUnauthorized && !*refreshed {
			*refreshed = true
			c.tokens.Invalidate(tok)
			continue
		}
		return body, classify("identity", status, h)
	}
}

func classify(op string, status int, h http.Header) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s: status %d", ErrUnauthorized, op, status)
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: %s: status %d", ErrInvalidRequest, op, status)
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &retryable{fmt.Errorf("%s: status %d", op, status), retryAfter(h)}
	}
	return fmt.Errorf("%w: %s: status %d", ErrUnavailable, op, status)
}

// authenticate is the TokenCache's fetcher: credentials from Secrets, then /auth.
func (c *Client) authenticate(ctx context.Context) (Token, error) {
	creds, err := c.secrets.VendorCredentials(ctx, c.cfg.SecretName)
	if err != nil {
		return Token{}, fmt.Errorf("credentials: %w", err)
	}
	status, h, body, err := c.post(ctx, "/auth", "", map[string]string{"username": creds.Username, "password": creds.Password})
	if err != nil {
		return Token{}, err
	}
	switch err := classify("auth", status, h); {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrInvalidRequest):
		// Not the lookup's fault: don't let the caller read it as "no match" or "bad input".
		return Token{}, fmt.Errorf("%w: auth: status %d", ErrUnavailable, status)
	case err != nil:
		return Token{}, err
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(body, &r) != nil || r.AccessToken == "" {
		return Token{}, fmt.Errorf("%w: malformed auth response", ErrUnavailable)
	}
	ttl := c.cfg.DefaultTokenTTL
	if r.ExpiresIn > 0 {
		ttl = time.Duration(r.ExpiresIn) * time.Second
	}
	return Token{AccessToken: r.AccessToken, ExpiresAt: c.cfg.Now().Add(ttl)}, nil
}

func (c *Client) post(ctx context.Context, path, bearer string, payload any) (int, http.Header, []byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, &retryable{err: err} // network error or this attempt's timeout
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return 0, nil, nil, &retryable{err: err}
	}
	if len(body) > maxBody { // checked, not just cut: a cut answer can still decode
		return 0, nil, nil, fmt.Errorf("%w: %s: response over %d bytes", ErrUnavailable, path, maxBody)
	}
	return resp.StatusCode, resp.Header, body, nil
}

func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if s, err := strconv.Atoi(v); err == nil {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

var alpha2 = regexp.MustCompile(`^[A-Z]{2}$`)

// normalise puts a vendor's answer in our formats: phone E.164, country
// ISO 3166-1 alpha-2 upper case. An answer that won't normalise is malformed.
func (c *Client) normalise(id *Identity) error {
	phone, err := profile.NormalizePhone(id.Phone)
	country := strings.ToUpper(strings.TrimSpace(id.Address.Country))
	if err != nil || country != "" && !alpha2.MatchString(country) {
		return fmt.Errorf("%w: malformed identity response", ErrUnavailable)
	}
	id.Provider, id.Phone, id.Address.Country = c.vendor, phone, country
	return nil
}
