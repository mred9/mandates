package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mred9/mandates/internal/store/storetest"
)

// The same contract runs against PostgreSQL and CockroachDB; docker-compose.yml provides both.
func TestContract(t *testing.T) {
	for _, env := range []string{"TEST_POSTGRES_DSN", "TEST_COCKROACH_DSN"} {
		t.Run(env, func(t *testing.T) {
			dsn := os.Getenv(env)
			if dsn == "" {
				t.Skipf("%s not set", env)
			}
			pool, err := Open(context.Background(), dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			storetest.Run(t, func(t *testing.T) storetest.Harness {
				return storetest.Harness{
					Profiles:    NewProfileStore(pool),
					Credentials: NewCredentialStore(pool),
					Exec: func(ctx context.Context, sql string) error {
						_, err := pool.Exec(ctx, sql)
						return err
					},
				}
			})
		})
	}
}

func TestWithRetry(t *testing.T) {
	serialization := &pgconn.PgError{Code: "40001"}
	other := errors.New("boom")

	for _, tc := range []struct {
		name      string
		errs      []error // returned by successive attempts; nil after the list ends
		wantCalls int
		wantErr   error
	}{
		{"succeeds first time", nil, 1, nil},
		{"retries 40001 then succeeds", []error{serialization, serialization}, 3, nil},
		{"gives up after max attempts", []error{serialization, serialization, serialization, serialization, serialization}, maxAttempts, serialization},
		{"does not retry other errors", []error{other}, 1, other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := withRetry(context.Background(), func(context.Context) error {
				calls++
				if calls <= len(tc.errs) {
					return tc.errs[calls-1]
				}
				return nil
			})
			if calls != tc.wantCalls || !errors.Is(err, tc.wantErr) {
				t.Fatalf("calls=%d err=%v; want calls=%d err=%v", calls, err, tc.wantCalls, tc.wantErr)
			}
		})
	}
}
