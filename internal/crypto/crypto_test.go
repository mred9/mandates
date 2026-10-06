package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestLocalKeyEnvelope(t *testing.T) {
	ctx := context.Background()
	env, err := NewLocalKeyEnvelope(key(1))
	if err != nil {
		t.Fatal(err)
	}
	dek, wrapped, err := env.GenerateDataKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != 32 || bytes.Contains(wrapped, dek) {
		t.Fatalf("want a 32-byte DEK that does not appear in its wrapped form")
	}

	got, err := env.DecryptDataKey(ctx, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: got %x, %v; want %x", got, err, dek)
	}

	wrapped[len(wrapped)-1] ^= 0xff
	if _, err := env.DecryptDataKey(ctx, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered wrapped key: got %v, want ErrDecrypt", err)
	}
}

func TestSealOpen(t *testing.T) {
	ct, err := Seal(key(2), []byte("Ada Lovelace"), []byte("row-1|name"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(key(2), ct, []byte("row-1|name")); err != nil || string(pt) != "Ada Lovelace" {
		t.Fatalf("round trip: got %q, %v", pt, err)
	}

	if _, err := Seal(key(2)[:16], []byte("x"), nil); err == nil {
		t.Fatal("Seal must refuse a key that would select AES-128")
	}

	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xff

	for name, tc := range map[string]struct {
		key, ct, aad []byte
	}{
		"wrong key": {key(3), ct, []byte("row-1|name")},
		"wrong aad": {key(2), ct, []byte("row-2|name")},
		"tampered":  {key(2), tampered, []byte("row-1|name")},
		"truncated": {key(2), ct[:5], []byte("row-1|name")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(tc.key, tc.ct, tc.aad); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestBlindIndex(t *testing.T) {
	if _, err := NewBlindIndex(nil); err == nil {
		t.Fatal("an empty blind-index key must be rejected")
	}
	a, _ := NewBlindIndex(key(4))
	b, _ := NewBlindIndex(key(5))
	if !bytes.Equal(a.Sum("+15551234567"), a.Sum("+15551234567")) {
		t.Fatal("blind index must be deterministic")
	}
	if bytes.Equal(a.Sum("+15551234567"), a.Sum("+15551234568")) {
		t.Fatal("different values must differ")
	}
	if bytes.Equal(a.Sum("+15551234567"), b.Sum("+15551234567")) {
		t.Fatal("blind index must depend on the key")
	}
}
