package credential

import (
	"errors"
	"strings"
	"testing"
)

// Cheap parameters keep the suite fast; production uses DefaultArgon2id.
var testHasher = Argon2id{Memory: 1024, Time: 1, Threads: 1}

func TestArgon2id(t *testing.T) {
	encoded, err := testHasher.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=1024,t=1,p=1$") || strings.Contains(encoded, "correct horse") {
		t.Fatalf("unexpected encoding %q", encoded)
	}
	if again, _ := testHasher.Hash("correct horse"); again == encoded {
		t.Fatal("hashes of the same password must differ (random salt)")
	}

	for _, tc := range []struct {
		password string
		want     bool
	}{
		{"correct horse", true},
		{"correct horsf", false},
		{"", false},
	} {
		ok, err := testHasher.Verify(tc.password, encoded)
		if err != nil || ok != tc.want {
			t.Errorf("Verify(%q) = %v, %v; want %v", tc.password, ok, err, tc.want)
		}
	}

	if _, err := testHasher.Verify("x", "$argon2id$garbage"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed hash: got %v, want ErrInvalid", err)
	}
}

func TestValidate(t *testing.T) {
	base := Credential{ID: "c1", UserID: "u1", Username: "ada"}
	with := func(m Method, f func(*Credential)) Credential {
		c := base
		c.Method = m
		f(&c)
		return c
	}
	password := func(c *Credential) { c.PasswordHash = "$argon2id$..." }
	passkey := func(c *Credential) { c.PasskeyID, c.PasskeyPublicKey = []byte{1}, []byte{2} }
	totp := func(c *Credential) { c.TOTPWrappedDEK, c.TOTPSecret = []byte{1}, []byte{2} }

	for _, tc := range []struct {
		name string
		c    Credential
		ok   bool
	}{
		{"password", with(MethodPassword, password), true},
		{"passkey", with(MethodPasskey, passkey), true},
		{"totp", with(MethodTOTP, totp), true},
		{"password missing hash", with(MethodPassword, func(*Credential) {}), false},
		{"password with passkey material", with(MethodPassword, func(c *Credential) { password(c); passkey(c) }), false},
		{"passkey missing public key", with(MethodPasskey, func(c *Credential) { c.PasskeyID = []byte{1} }), false},
		{"totp with password hash", with(MethodTOTP, func(c *Credential) { totp(c); password(c) }), false},
		{"unknown method", with("sms", password), false},
		{"missing username", func() Credential { c := with(MethodPassword, password); c.Username = ""; return c }(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Fatalf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
