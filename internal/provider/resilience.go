package provider

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// Breaker stops calls to a failing vendor. It is closed until threshold
// consecutive lookups fail, then open for cooldown, then lets one probe through.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	mu       sync.Mutex
	failures int
	openedAt time.Time
	probing  bool
}

func NewBreaker(threshold int, cooldown time.Duration, now func() time.Time) *Breaker {
	return &Breaker{threshold: threshold, cooldown: cooldown, now: now}
}

func (b *Breaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return nil
	}
	if b.probing || b.now().Before(b.openedAt.Add(b.cooldown)) {
		return ErrCircuitOpen
	}
	b.probing = true
	return nil
}

// Record counts ErrUnavailable as a failure and any other answer from the
// vendor (an identity, not found, bad request) as a success. The caller giving
// up says nothing about the vendor, so it counts as neither.
func (b *Breaker) Record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	switch {
	case errors.Is(err, ErrUnavailable):
		if b.failures++; b.failures >= b.threshold {
			b.openedAt = b.now()
		}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
	default:
		b.failures = 0
	}
}

// retryable marks an attempt's failure as transient; after is the vendor's Retry-After.
type retryable struct {
	err   error
	after time.Duration
}

func (r *retryable) Error() string { return r.err.Error() }
func (r *retryable) Unwrap() error { return r.err }

// Do runs one vendor call through the breaker, with a timeout per attempt and
// retries for transient failures only.
func Do(ctx context.Context, cfg VendorConfig, b *Breaker, call func(ctx context.Context) error) error {
	if err := b.Allow(); err != nil {
		return err
	}
	err := attempt(ctx, cfg, call)
	b.Record(err)
	return err
}

func attempt(ctx context.Context, cfg VendorConfig, call func(ctx context.Context) error) error {
	var err error
	for n := range cfg.MaxAttempts {
		if n > 0 {
			if werr := wait(ctx, backoff(cfg, n, err)); werr != nil {
				return werr
			}
		}
		actx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		err = call(actx)
		cancel()
		var r *retryable
		switch {
		case err == nil:
			return nil
		case ctx.Err() != nil: // the caller gave up: don't retry, and don't blame the vendor
			return ctx.Err()
		case !errors.As(err, &r) && !errors.Is(err, context.DeadlineExceeded): // permanent
			return err
		}
	}
	// %v, not %w: an attempt's own timeout must not read as the caller's context error.
	return fmt.Errorf("%w after %d attempts: %v", ErrUnavailable, cfg.MaxAttempts, err)
}

// backoff is the vendor's Retry-After if it sent one, else full jitter, both capped at BackoffMax.
func backoff(cfg VendorConfig, n int, last error) time.Duration {
	var r *retryable
	if errors.As(last, &r) && r.after > 0 {
		return min(r.after, cfg.BackoffMax)
	}
	ceiling := min(cfg.BackoffMax, cfg.BackoffBase<<min(n-1, 30))
	if ceiling <= 0 {
		return 0
	}
	return rand.N(ceiling)
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
