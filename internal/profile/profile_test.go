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
	index, err := crypto.NewBlindIndex(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &memStore{}
	return NewRepository(store, env, index), store
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

func TestCiphertextIsBoundToItsRowAndColumn(t *testing.T) {
	ctx := context.Background()
	repo, store := newRepo(t)
	a, _ := repo.Create(ctx, ada)
	b, _ := repo.Create(ctx, ada)

	// Move all of a's sealed data, key included, under b's ID.
	moved := store.rows[0]
	moved.ID = b.ID
	store.rows[1] = moved
	if _, err := repo.Get(ctx, b.ID); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("row copied under another ID: got %v, want ErrDecrypt", err)
	}

	// Swap two columns within one row.
	r := &store.rows[0]
	r.Name, r.Phone = r.Phone, r.Name
	if _, err := repo.Get(ctx, a.ID); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("columns swapped: got %v, want ErrDecrypt", err)
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
	for name, tc := range map[string]struct {
		phone, after string
		limit        int
	}{
		"invalid phone":   {"nope", "", 2},
		"zero limit":      {"+15551234567", "", 0},
		"negative limit":  {"+15551234567", "", -1},
		"limit too large": {"+15551234567", "", 101},
		"malformed after": {"+15551234567", "garbage", 2},
	} {
		if _, err := repo.Search(ctx, tc.phone, tc.after, tc.limit); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestSearchRejectsTamperedIndex(t *testing.T) {
	ctx := context.Background()
	repo, store := newRepo(t)
	if _, err := repo.Create(ctx, ada); err != nil {
		t.Fatal(err)
	}
	victim := ada
	victim.Phone = "+447700900123"
	if _, err := repo.Create(ctx, victim); err != nil {
		t.Fatal(err)
	}
	// Someone with write access points the victim's index at Ada's number.
	store.rows[1].PhoneIndex = store.rows[0].PhoneIndex
	got, err := repo.Search(ctx, ada.Phone, "", 10)
	if err == nil || len(got) != 0 {
		t.Fatalf("got %d results, %v; want an error and no PII", len(got), err)
	}
}

func TestProfileLogsWithoutPII(t *testing.T) {
	var buf bytes.Buffer
	p := ada
	p.ID = "0192-test"
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("loaded", "profile", p, "address", p.Address)
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

// strictStore fails any Get it receives, like a database rejecting bytes it can't parse.
type strictStore struct{ memStore }

func (*strictStore) Get(context.Context, string) (Sealed, error) {
	return Sealed{}, errors.New("store rejected the id")
}

func TestGetMalformedIDIsNotFoundWithoutTheStore(t *testing.T) {
	repo, _ := newRepo(t)
	repo.store = &strictStore{}
	for _, id := range []string{"not-a-uuid", "\xff", "a\x00b", "", "{0192f2c4-0000-7000-8000-000000000000\x00", "{0192f2c4-0000-7000-8000-000000000000\xff"} {
		if _, err := repo.Get(context.Background(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v, want ErrNotFound", id, err)
		}
	}
}
