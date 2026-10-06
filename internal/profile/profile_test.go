package profile

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/mred9/mandates/internal/crypto"
)

// memStore records what the repository hands it, so tests can inspect it.
type memStore struct{ rows []Sealed }

func (m *memStore) Create(_ context.Context, s Sealed) error {
	m.rows = append(m.rows, s)
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (Sealed, error) {
	for _, r := range m.rows {
		if r.ID == id {
			return r, nil
		}
	}
	return Sealed{}, ErrNotFound
}

func (m *memStore) FindByPhoneIndex(_ context.Context, idx []byte, after string, limit int) ([]Sealed, error) {
	var out []Sealed
	for _, r := range m.rows {
		if bytes.Equal(r.PhoneIndex, idx) && r.ID > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func newRepo(t *testing.T) (*Repository, *memStore) {
	t.Helper()
	env, err := crypto.NewLocalKeyEnvelope(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &memStore{}
	return NewRepository(store, env, crypto.NewBlindIndex(bytes.Repeat([]byte{2}, 32))), store
}

var ada = Profile{
	Name:  "Ada Lovelace",
	Phone: "+1 (555) 123-4567",
	Address: Address{
		StreetAddress: "12 St James's Square", Locality: "London",
		Region: "Greater London", PostalCode: "SW1Y 4JH", Country: "GB",
	},
}

func TestCreateGetRoundTripsWithoutPlaintextInStore(t *testing.T) {
	ctx := context.Background()
	repo, store := newRepo(t)

	created, err := repo.Create(ctx, ada)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Phone != "+15551234567" {
		t.Fatalf("want an ID and an E.164 phone, got %+v", created)
	}

	got, err := repo.Get(ctx, created.ID)
	if err != nil || got != created {
		t.Fatalf("Get = %+v, %v; want %+v", got, err, created)
	}

	row := store.rows[0]
	stored := slices.Concat(row.WrappedDEK, row.Name, row.Phone, row.Address, row.PhoneIndex)
	for _, pii := range []string{"Ada", "5551234567", "London", "SW1Y"} {
		if bytes.Contains(stored, []byte(pii)) {
			t.Errorf("store received plaintext %q", pii)
		}
	}
}

func TestCiphertextIsBoundToItsRow(t *testing.T) {
	ctx := context.Background()
	repo, store := newRepo(t)
	a, _ := repo.Create(ctx, ada)
	b, _ := repo.Create(ctx, ada)

	// Copy a's name ciphertext and key into b's row: decryption must fail.
	store.rows[1].Name, store.rows[1].WrappedDEK = store.rows[0].Name, store.rows[0].WrappedDEK
	if _, err := repo.Get(ctx, b.ID); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("swapped ciphertext: got %v, want ErrDecrypt", err)
	}
	if _, err := repo.Get(ctx, a.ID); err != nil {
		t.Fatalf("untouched row: %v", err)
	}
}

func TestValidation(t *testing.T) {
	repo, _ := newRepo(t)
	for name, p := range map[string]Profile{
		"empty name":    {Name: " ", Phone: "+15551234567"},
		"short phone":   {Name: "Ada", Phone: "123"},
		"letters":       {Name: "Ada", Phone: "+1555CALLADA"},
		"leading zero":  {Name: "Ada", Phone: "+05551234567"},
		"missing phone": {Name: "Ada"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := repo.Create(context.Background(), p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	if _, err := repo.Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get unknown: got %v, want ErrNotFound", err)
	}
}

func TestSearchByPhone(t *testing.T) {
	ctx := context.Background()
	repo, _ := newRepo(t)
	var ids []string
	for range 3 {
		p, err := repo.Create(ctx, ada)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.ID)
	}
	other := ada
	other.Phone = "+447700900123"
	if _, err := repo.Create(ctx, other); err != nil {
		t.Fatal(err)
	}

	page1, err := repo.Search(ctx, "+1 555-123-4567", "", 2) // different formatting, same number
	if err != nil || len(page1) != 2 {
		t.Fatalf("page 1: %d results, %v", len(page1), err)
	}
	page2, err := repo.Search(ctx, "+15551234567", page1[1].ID, 2)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page 2: %d results, %v", len(page2), err)
	}
	got := []string{page1[0].ID, page1[1].ID, page2[0].ID}
	if !slices.Equal(got, ids) {
		t.Fatalf("got %v, want %v in ID order", got, ids)
	}
	if _, err := repo.Search(ctx, "nope", "", 2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid phone: got %v, want ErrInvalid", err)
	}
}

func TestProfileLogsWithoutPII(t *testing.T) {
	var buf bytes.Buffer
	p := ada
	p.ID = "0192-test"
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("loaded", "profile", p)
	out := buf.String()
	if !strings.Contains(out, "0192-test") {
		t.Fatalf("ID should be logged: %s", out)
	}
	for _, pii := range []string{"Ada", "555", "London"} {
		if strings.Contains(out, pii) {
			t.Errorf("log contains %q: %s", pii, out)
		}
	}
}
