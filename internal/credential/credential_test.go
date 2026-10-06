package credential

import (
	"bytes"
	"errors"
	"log/slog"
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

	for _, bad := range []string{
		"$argon2id$garbage",
		"$argon2id$v=19$m=1024,t=0,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA", // t=0 panics inside argon2
		"$argon2id$v=19$m=1024,t=1,p=0$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA", // p=0 panics inside argon2
		"$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$$aGFzaGhhc2hoYXNoaGFzaA", // empty salt
	} {
		if _, err := testHasher.Verify("x", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("Verify(%q): got %v, want ErrInvalid", bad, err)
		}
	}
}

func TestCredentialLogsWithoutSecrets(t *testing.T) {
	var buf bytes.Buffer
	c := Credential{ID: "c1", Username: "ada", Method: MethodPassword, PasswordHash: "$argon2id$secret"}
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("loaded", "credential", c)
	if strings.Contains(buf.String(), "argon2id") || !strings.Contains(buf.String(), "c1") {
		t.Fatalf("want ID only: %s", buf.String())
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
