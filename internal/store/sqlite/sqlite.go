// Package sqlite implements profile.Store and credential.Store on SQLite
// (modernc.org/sqlite: pure Go, no cgo).
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/mred9/mandates/internal/credential"
	"github.com/mred9/mandates/internal/profile"
)

//go:embed migrations/*.up.sql
var migrations embed.FS

// Open opens the database file at path and applies migrations.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// TODO: a versioned runner (goose, atlas) once there is a second migration;
	// 0001 is idempotent DDL, so re-running it is safe.
	up, err := migrations.ReadFile("migrations/0001_init.up.sql")
	if err == nil {
		_, err = db.ExecContext(ctx, string(up))
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}
	return db, nil
}

type ProfileStore struct{ db *sql.DB }

func NewProfileStore(db *sql.DB) *ProfileStore { return &ProfileStore{db: db} }

func (s *ProfileStore) Create(ctx context.Context, p profile.Sealed) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_profiles (id, wrapped_dek, name_ct, phone_ct, address_ct, phone_bidx, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.WrappedDEK, p.Name, p.Phone, p.Address, p.PhoneIndex, p.CreatedAt)
	if isUnique(err) {
		return profile.ErrConflict
	}
	return err
}

const profileCols = `id, wrapped_dek, name_ct, phone_ct, address_ct, phone_bidx, created_at`

func scanProfile(row interface{ Scan(...any) error }) (profile.Sealed, error) {
	var p profile.Sealed
	err := row.Scan(&p.ID, &p.WrappedDEK, &p.Name, &p.Phone, &p.Address, &p.PhoneIndex, &p.CreatedAt)
	return p, err
}

func (s *ProfileStore) Get(ctx context.Context, id string) (profile.Sealed, error) {
	p, err := scanProfile(s.db.QueryRowContext(ctx, `SELECT `+profileCols+` FROM user_profiles WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return profile.Sealed{}, profile.ErrNotFound
	}
	return p, err
}

func (s *ProfileStore) FindByPhoneIndex(ctx context.Context, index []byte, after string, limit int) ([]profile.Sealed, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+profileCols+` FROM user_profiles WHERE phone_bidx = ? AND id > ? ORDER BY id LIMIT ?`,
		index, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []profile.Sealed
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type CredentialStore struct{ db *sql.DB }

func NewCredentialStore(db *sql.DB) *CredentialStore { return &CredentialStore{db: db} }

func (s *CredentialStore) Create(ctx context.Context, c credential.Credential) error {
	if err := c.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_credentials (id, user_id, username, method, password_hash,
		     passkey_credential_id, passkey_public_key, totp_wrapped_dek, totp_secret_ct, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.Username, c.Method, nullString(c.PasswordHash),
		c.PasskeyID, c.PasskeyPublicKey, c.TOTPWrappedDEK, c.TOTPSecret, c.CreatedAt)
	if isUnique(err) {
		return credential.ErrConflict
	}
	return err
}

func (s *CredentialStore) FindByUsername(ctx context.Context, username string, m credential.Method) ([]credential.Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, username, method, password_hash, passkey_credential_id, passkey_public_key,
		        totp_wrapped_dek, totp_secret_ct, created_at
		 FROM user_credentials WHERE username = ? AND method = ? ORDER BY id`, username, m)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []credential.Credential
	for rows.Next() {
		var c credential.Credential
		var hash sql.NullString
		if err := rows.Scan(&c.ID, &c.UserID, &c.Username, &c.Method, &hash, &c.PasskeyID,
			&c.PasskeyPublicKey, &c.TOTPWrappedDEK, &c.TOTPSecret, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.PasswordHash = hash.String
		out = append(out, c)
	}
	return out, rows.Err()
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func isUnique(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) &&
		(e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY)
}
