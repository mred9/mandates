// Package storetest is the contract every store implementation must pass.
// Each dialect's tests call Run; no dialect gets its own behavioural tests.
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mred9/mandates/internal/credential"
	"github.com/mred9/mandates/internal/profile"
)

type Harness struct {
	Profiles    profile.Store
	Credentials credential.Store
	// Exec runs raw SQL so the suite can check constraints the database itself enforces.
	Exec func(ctx context.Context, sql string) error
}

// Run executes the contract. Tests use fresh random data, so they need no
// cleanup and can share a database.
func Run(t *testing.T, newHarness func(t *testing.T) Harness) {
	tests := map[string]func(*testing.T, Harness){
		"profile round trip":                   profileRoundTrip,
		"profile not found and conflict":       profileNotFoundAndConflict,
		"phone index search pages by ID":       phoneIndexPaging,
		"duplicate password username":          duplicatePasswordUsername,
		"several passkeys per user":            severalPasskeys,
		"database rejects mismatched payloads": databaseRejectsMismatch,
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) { test(t, newHarness(t)) })
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func newSealed(index []byte) profile.Sealed {
	return profile.Sealed{
		ID:         uuid.Must(uuid.NewV7()).String(),
		WrappedDEK: randBytes(60),
		Name:       randBytes(40),
		Phone:      randBytes(40),
		Address:    randBytes(120),
		PhoneIndex: index,
		CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
	}
}

func mustCreateProfile(t *testing.T, h Harness) profile.Sealed {
	t.Helper()
	s := newSealed(randBytes(32))
	if err := h.Profiles.Create(context.Background(), s); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	return s
}

func profileRoundTrip(t *testing.T, h Harness) {
	want := mustCreateProfile(t, h)
	got, err := h.Profiles.Get(context.Background(), want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || !got.CreatedAt.Equal(want.CreatedAt) ||
		!bytes.Equal(got.WrappedDEK, want.WrappedDEK) || !bytes.Equal(got.Name, want.Name) ||
		!bytes.Equal(got.Phone, want.Phone) || !bytes.Equal(got.Address, want.Address) ||
		!bytes.Equal(got.PhoneIndex, want.PhoneIndex) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func profileNotFoundAndConflict(t *testing.T, h Harness) {
	ctx := context.Background()
	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		if _, err := h.Profiles.Get(ctx, id); !errors.Is(err, profile.ErrNotFound) {
			t.Fatalf("get %q: got %v, want ErrNotFound", id, err)
		}
	}
	s := mustCreateProfile(t, h)
	if err := h.Profiles.Create(ctx, s); !errors.Is(err, profile.ErrConflict) {
		t.Fatalf("duplicate ID: got %v, want ErrConflict", err)
	}
}

func phoneIndexPaging(t *testing.T, h Harness) {
	ctx := context.Background()
	index := randBytes(32)
	var want []string
	for range 3 {
		s := newSealed(index)
		if err := h.Profiles.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		want = append(want, s.ID)
	}
	mustCreateProfile(t, h) // different index, must not appear

	page1, err := h.Profiles.FindByPhoneIndex(ctx, index, "", 2)
	if err != nil || len(page1) != 2 {
		t.Fatalf("page 1: %d rows, %v", len(page1), err)
	}
	page2, err := h.Profiles.FindByPhoneIndex(ctx, index, page1[1].ID, 2)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page 2: %d rows, %v", len(page2), err)
	}
	got := []string{page1[0].ID, page1[1].ID, page2[0].ID}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func newCredential(userID, username string, m credential.Method) credential.Credential {
	c := credential.Credential{
		ID: uuid.NewString(), UserID: userID, Username: username, Method: m,
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	switch m {
	case credential.MethodPassword:
		c.PasswordHash = "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA"
	case credential.MethodPasskey:
		c.PasskeyID, c.PasskeyPublicKey = randBytes(32), randBytes(77)
	}
	return c
}

func duplicatePasswordUsername(t *testing.T, h Harness) {
	ctx := context.Background()
	user := mustCreateProfile(t, h)
	username := "user-" + uuid.NewString()
	if err := h.Credentials.Create(ctx, newCredential(user.ID, username, credential.MethodPassword)); err != nil {
		t.Fatal(err)
	}
	err := h.Credentials.Create(ctx, newCredential(user.ID, username, credential.MethodPassword))
	if !errors.Is(err, credential.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	got, err := h.Credentials.FindByUsername(ctx, username, credential.MethodPassword)
	if err != nil || len(got) != 1 || got[0].PasswordHash == "" || got[0].UserID != user.ID {
		t.Fatalf("FindByUsername = %+v, %v", got, err)
	}
}

func severalPasskeys(t *testing.T, h Harness) {
	ctx := context.Background()
	user := mustCreateProfile(t, h)
	username := "user-" + uuid.NewString()
	for range 2 {
		if err := h.Credentials.Create(ctx, newCredential(user.ID, username, credential.MethodPasskey)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := h.Credentials.FindByUsername(ctx, username, credential.MethodPasskey)
	if err != nil || len(got) != 2 || len(got[0].PasskeyPublicKey) == 0 {
		t.Fatalf("FindByUsername = %d rows, %v", len(got), err)
	}
}

// databaseRejectsMismatch bypasses Credential.Validate: the schema must hold
// the rule on its own.
func databaseRejectsMismatch(t *testing.T, h Harness) {
	user := mustCreateProfile(t, h)
	err := h.Exec(context.Background(), fmt.Sprintf(
		`INSERT INTO user_credentials (id, user_id, username, method, created_at)
		 VALUES ('%s', '%s', 'no-hash', 'password', '2026-01-01T00:00:00Z')`, uuid.NewString(), user.ID))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("password credential without a hash: got %v, want a CHECK constraint violation", err)
	}
}
