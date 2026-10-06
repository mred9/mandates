// Package postgres implements profile.Store and credential.Store with pgx,
// for both PostgreSQL and CockroachDB (one code path, one migration set).
package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mred9/mandates/internal/credential"
	"github.com/mred9/mandates/internal/profile"
)

//go:embed migrations/0001_init.up.sql
var migration string

// Open connects and applies migrations.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	// TODO: a versioned runner (goose, atlas) once there is a second migration;
	// 0001 is idempotent DDL, so re-running it is safe.
	if _, err := pool.Exec(ctx, migration); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}
	return pool, nil
}

const maxAttempts = 5

// withRetry re-runs fn when the database reports a serialization failure
// (SQLSTATE 40001). CockroachDB runs every transaction SERIALIZABLE and asks
// clients to retry; PostgreSQL returns the same code at SERIALIZABLE. Any other
// error is returned at once. Writes go through it; reads are single statements
// that CockroachDB retries server-side where it can. fn must be safe to repeat: a whole statement or
// a whole transaction, never half of one.
func withRetry(ctx context.Context, fn func(context.Context) error) error {
	var err error
	for attempt := range maxAttempts {
		if err = fn(ctx); !isCode(err, "40001") || attempt == maxAttempts-1 {
			return err
		}
		backoff := time.Duration(rand.Int64N(int64(5*time.Millisecond) << attempt)) // full jitter
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(backoff):
		}
	}
	return err
}

func isCode(err error, code string) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == code
}

const uniqueViolation = "23505"

// zeroUUID sorts before every UUID, so an empty cursor means "from the start".
const zeroUUID = "00000000-0000-0000-0000-000000000000"

type ProfileStore struct{ pool *pgxpool.Pool }

func NewProfileStore(pool *pgxpool.Pool) *ProfileStore { return &ProfileStore{pool: pool} }

func (s *ProfileStore) Create(ctx context.Context, p profile.Sealed) error {
	err := withRetry(ctx, func(ctx context.Context) error {
		_, err := s.pool.Exec(ctx,
			`INSERT INTO user_profiles (id, wrapped_dek, name_ct, phone_ct, address_ct, phone_bidx, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			p.ID, p.WrappedDEK, p.Name, p.Phone, p.Address, p.PhoneIndex, p.CreatedAt)
		return err
	})
	if isCode(err, uniqueViolation) {
		return profile.ErrConflict
	}
	return err
}

const profileCols = `id::text, wrapped_dek, name_ct, phone_ct, address_ct, phone_bidx, created_at`

func scanProfile(row pgx.Row) (profile.Sealed, error) {
	var p profile.Sealed
	err := row.Scan(&p.ID, &p.WrappedDEK, &p.Name, &p.Phone, &p.Address, &p.PhoneIndex, &p.CreatedAt)
	return p, err
}

func (s *ProfileStore) Get(ctx context.Context, id string) (profile.Sealed, error) {
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileCols+` FROM user_profiles WHERE id = $1`, id))
	// A malformed ID is indistinguishable from a missing one, by design.
	if errors.Is(err, pgx.ErrNoRows) || isCode(err, "22P02") {
		return profile.Sealed{}, profile.ErrNotFound
	}
	return p, err
}

func (s *ProfileStore) FindByPhoneIndex(ctx context.Context, index []byte, after string, limit int) ([]profile.Sealed, error) {
	if after == "" {
		after = zeroUUID
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+profileCols+` FROM user_profiles WHERE phone_bidx = $1 AND id > $2 ORDER BY id LIMIT $3`,
		index, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (profile.Sealed, error) { return scanProfile(r) })
}

type CredentialStore struct{ pool *pgxpool.Pool }

func NewCredentialStore(pool *pgxpool.Pool) *CredentialStore { return &CredentialStore{pool: pool} }

func (s *CredentialStore) Create(ctx context.Context, c credential.Credential) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var hash *string
	if c.PasswordHash != "" {
		hash = &c.PasswordHash
	}
	err := withRetry(ctx, func(ctx context.Context) error {
		_, err := s.pool.Exec(ctx,
			`INSERT INTO user_credentials (id, user_id, username, method, password_hash,
			     passkey_credential_id, passkey_public_key, totp_wrapped_dek, totp_secret_ct, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			c.ID, c.UserID, c.Username, string(c.Method), hash,
			c.PasskeyID, c.PasskeyPublicKey, c.TOTPWrappedDEK, c.TOTPSecret, c.CreatedAt)
		return err
	})
	if isCode(err, uniqueViolation) {
		return credential.ErrConflict
	}
	return err
}

func (s *CredentialStore) FindByUsername(ctx context.Context, username string, m credential.Method) ([]credential.Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, user_id::text, username, method, password_hash, passkey_credential_id,
		        passkey_public_key, totp_wrapped_dek, totp_secret_ct, created_at
		 FROM user_credentials WHERE username = $1 AND method = $2 ORDER BY id`, username, string(m))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (credential.Credential, error) {
		var c credential.Credential
		var method string
		var hash *string
		err := row.Scan(&c.ID, &c.UserID, &c.Username, &method, &hash, &c.PasskeyID,
			&c.PasskeyPublicKey, &c.TOTPWrappedDEK, &c.TOTPSecret, &c.CreatedAt)
		c.Method = credential.Method(method)
		if hash != nil {
			c.PasswordHash = *hash
		}
		return c, err
	})
}
