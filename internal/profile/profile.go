// Package profile stores user PII encrypted at rest. Repository is the DAO
// callers use; Store implementations only ever see ciphertext.
package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mred9/mandates/internal/crypto"
)

var (
	ErrNotFound = errors.New("profile: not found")
	ErrInvalid  = errors.New("profile: invalid")
	ErrConflict = errors.New("profile: conflict")
)

type Address struct {
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

// LogValue redacts an Address logged on its own.
func (Address) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type Profile struct {
	ID        string
	Name      string
	Phone     string // E.164
	Address   Address
	CreatedAt time.Time
}

// LogValue keeps PII out of logs even when a whole Profile is logged by mistake.
func (p Profile) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", p.ID), slog.String("pii", "[REDACTED]"))
}

// Sealed is the persisted form of a Profile: one wrapped DEK per row and
// each PII field encrypted under it.
type Sealed struct {
	ID         string
	WrappedDEK []byte
	Name       []byte
	Phone      []byte
	Address    []byte // ciphertext of JSON-encoded Address
	PhoneIndex []byte // blind index of the E.164 phone
	CreatedAt  time.Time
}

// Store is the ProfileStore.
type Store interface {
	Create(ctx context.Context, s Sealed) error
	Get(ctx context.Context, id string) (Sealed, error)
	// FindByPhoneIndex returns up to limit rows with ID > after, ordered by ID.
	FindByPhoneIndex(ctx context.Context, index []byte, after string, limit int) ([]Sealed, error)
}

type Repository struct {
	store Store
	env   crypto.Envelope
	index *crypto.BlindIndex
}

func NewRepository(s Store, env crypto.Envelope, index *crypto.BlindIndex) *Repository {
	return &Repository{store: s, env: env, index: index}
}

func (r *Repository) Create(ctx context.Context, p Profile) (Profile, error) {
	phone, err := NormalizePhone(p.Phone)
	if err != nil {
		return Profile{}, err
	}
	if strings.TrimSpace(p.Name) == "" {
		return Profile{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	id, err := uuid.NewV7() // time-ordered, so keyset paging by ID is stable
	if err != nil {
		return Profile{}, fmt.Errorf("profile: id: %w", err)
	}
	p.ID, p.Phone, p.CreatedAt = id.String(), phone, time.Now().UTC().Truncate(time.Microsecond)

	dek, wrapped, err := r.env.GenerateDataKey(ctx)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: data key: %w", err)
	}
	defer clear(dek)

	addr, err := json.Marshal(p.Address)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: address: %w", err)
	}
	s := Sealed{ID: p.ID, WrappedDEK: wrapped, PhoneIndex: r.index.Sum(phone), CreatedAt: p.CreatedAt}
	for _, f := range []struct {
		dst   *[]byte
		col   string
		plain []byte
	}{{&s.Name, "name", []byte(p.Name)}, {&s.Phone, "phone", []byte(phone)}, {&s.Address, "address", addr}} {
		if *f.dst, err = crypto.Seal(dek, f.plain, aad(p.ID, f.col)); err != nil {
			return Profile{}, fmt.Errorf("profile: seal %s: %w", f.col, err)
		}
	}
	if err := r.store.Create(ctx, s); err != nil {
		return Profile{}, fmt.Errorf("profile: create: %w", err)
	}
	return p, nil
}

func (r *Repository) Get(ctx context.Context, id string) (Profile, error) {
	// A malformed ID can't exist. Checking here gives every store the same
	// answer; PostgreSQL would otherwise reject invalid UTF-8 with an error.
	if _, err := uuid.Parse(id); err != nil {
		return Profile{}, fmt.Errorf("profile: get: %w", ErrNotFound)
	}
	s, err := r.store.Get(ctx, id)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: get: %w", err)
	}
	return r.open(ctx, s)
}

// MaxPageSize bounds Search so one call cannot return an unbounded result.
const MaxPageSize = 100

// Search is an exact match on phone through the blind index, paged by ID.
// after is the last ID of the previous page, or "" for the first page.
func (r *Repository) Search(ctx context.Context, phone, after string, limit int) ([]Profile, error) {
	phone, err := NormalizePhone(phone)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxPageSize {
		return nil, fmt.Errorf("%w: limit must be 1..%d", ErrInvalid, MaxPageSize)
	}
	if _, err := uuid.Parse(after); after != "" && err != nil {
		return nil, fmt.Errorf("%w: malformed cursor", ErrInvalid)
	}
	rows, err := r.store.FindByPhoneIndex(ctx, r.index.Sum(phone), after, limit)
	if err != nil {
		return nil, fmt.Errorf("profile: search: %w", err)
	}
	out := make([]Profile, 0, len(rows))
	for _, s := range rows {
		p, err := r.open(ctx, s)
		if err != nil {
			return nil, err
		}
		// phone_bidx is not authenticated; check the decrypted phone so a
		// tampered index cannot return someone else's PII.
		if p.Phone != phone {
			return nil, fmt.Errorf("profile: blind index does not match row %s", s.ID)
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *Repository) open(ctx context.Context, s Sealed) (Profile, error) {
	dek, err := r.env.DecryptDataKey(ctx, s.WrappedDEK)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: data key: %w", err)
	}
	defer clear(dek)

	field := func(col string, sealed []byte) []byte {
		if err != nil {
			return nil
		}
		var plain []byte
		if plain, err = crypto.Open(dek, sealed, aad(s.ID, col)); err != nil {
			err = fmt.Errorf("profile: open %s: %w", col, err)
		}
		return plain
	}
	p := Profile{ID: s.ID, CreatedAt: s.CreatedAt.UTC(), Name: string(field("name", s.Name)), Phone: string(field("phone", s.Phone))}
	addr := field("address", s.Address)
	if err != nil {
		return Profile{}, err
	}
	if err := json.Unmarshal(addr, &p.Address); err != nil {
		return Profile{}, fmt.Errorf("profile: address: %w", err)
	}
	return p, nil
}

// aad binds a ciphertext to its row and column.
func aad(id, column string) []byte { return []byte(id + "|" + column) }

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

// NormalizePhone strips formatting and requires E.164, so equal numbers give
// equal blind indexes.
func NormalizePhone(s string) (string, error) {
	n := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", ".", "").Replace(s)
	if !e164.MatchString(n) {
		return "", fmt.Errorf("%w: phone must be E.164", ErrInvalid)
	}
	return n, nil
}
