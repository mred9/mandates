package credential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id hashes passwords into PHC strings:
// $argon2id$v=19$m=<KiB>,t=<iterations>,p=<threads>$<salt>$<hash>
type Argon2id struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

// DefaultArgon2id is RFC 9106's second recommended option (64 MiB, t=3, p=4).
var DefaultArgon2id = Argon2id{Memory: 64 * 1024, Time: 3, Threads: 4}

const (
	saltLen, keyLen = 16, 32
	maxMemory       = 1 << 20 // 1 GiB in KiB
)

var b64 = base64.RawStdEncoding

func (a Argon2id) Hash(password string) (string, error) {
	if !a.valid() {
		return "", fmt.Errorf("%w: argon2id parameters out of range", ErrInvalid)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("credential: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, a.Time, a.Memory, a.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s",
		argon2.Version, a.params(), b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func (a Argon2id) params() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", a.Memory, a.Time, a.Threads)
}

// valid bounds the parameters: argon2.IDKey panics on t=0 or p=0, and m is an
// allocation size, so values read from storage are checked before use.
func (a Argon2id) valid() bool {
	return a.Time >= 1 && a.Time <= 10 && a.Threads >= 1 &&
		a.Memory >= 8*uint32(a.Threads) && a.Memory <= maxMemory
}

// Verify recomputes the hash with the parameters stored in encoded and
// compares in constant time.
func (Argon2id) Verify(password, encoded string) (bool, error) {
	malformed := fmt.Errorf("%w: malformed argon2id hash", ErrInvalid)
	parts := strings.Split(encoded, "$") // "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false, malformed
	}
	var p Argon2id
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads)
	if err != nil || parts[3] != p.params() || !p.valid() { // Sscanf ignores trailing text
		return false, malformed
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(want) < 16 || len(want) > 64 {
		return false, malformed
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
