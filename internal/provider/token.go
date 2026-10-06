package provider

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

func (Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type TokenFetcher func(ctx context.Context) (Token, error)

// TokenCache holds one vendor access token. It refreshes the token when it is
// within refreshBefore of expiry, and concurrent callers share one refresh.
type TokenCache struct {
	fetch         TokenFetcher
	refreshBefore time.Duration
	now           func() time.Time

	mu    sync.Mutex
	tok   Token
	group singleflight.Group
}

func NewTokenCache(fetch TokenFetcher, refreshBefore time.Duration, now func() time.Time) *TokenCache {
	return &TokenCache{fetch: fetch, refreshBefore: refreshBefore, now: now}
}

// Token returns the cached token, or fetches one. The fetch runs under the
// first caller's context; callers sharing it get its error too.
func (c *TokenCache) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	tok := c.tok
	c.mu.Unlock()
	if tok.AccessToken != "" && c.now().Before(tok.ExpiresAt.Add(-c.refreshBefore)) {
		return tok.AccessToken, nil
	}
	v, err, _ := c.group.Do("token", func() (any, error) {
		fresh, err := c.fetch(ctx)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.tok = fresh
		c.mu.Unlock()
		return fresh.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// Invalidate drops the cached token if it is still stale, so a caller that
// saw a 401 doesn't throw away a token another caller has just fetched.
func (c *TokenCache) Invalidate(stale string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok.AccessToken == stale {
		c.tok = Token{}
	}
}
