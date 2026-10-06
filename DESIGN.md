# DESIGN

One section per question: the decisions, the trade-offs, and what I would do with more time.
The code is a small proof of concept; the reasoning is here.

---

## Q1: Database DAO

### Shape

```
            plaintext Profile                        ciphertext only
caller ───────────────────────▶ profile.Repository ───────────────────▶ profile.Store
                                  │  envelope encrypt                       ├─ sqlite.ProfileStore
                                  │  blind index                            └─ postgres.ProfileStore
                                  ▼                                              (PostgreSQL + CockroachDB)
                               crypto.Envelope ── LocalKeyEnvelope (dev) / VaultTransitEnvelope (stub)
```

### Decisions

**Two stores, two tables.** `profile.Store` and `credential.Store` are separate interfaces, and
each dialect gives them separate types over separate connections. Profiles are read by a
customer-facing API; credentials are read only by the login path. Keeping them apart lets
each sit under its own database role: the API's role never gets `SELECT` on `user_credentials`,
so a bug in the API, or a compromise of it, can't reach password hashes. One interface with
both would make that separation a convention instead of a grant.

**Encryption belongs in the repository, not the stores.** `profile.Repository` seals and opens.
Stores receive `profile.Sealed`, which is ciphertext and a blind index, and never see plaintext.
That means the crypto is written once rather than per dialect, the dialect code is plain SQL, and
a test can check what reaches the store (`TestCreateGetRoundTripsWithoutPlaintextInStore`).

**Envelope encryption, one data key per row.** Each profile gets a fresh 256-bit DEK, wrapped by a
KEK that lives in the key service. Only the wrapped DEK is stored. Consequences:
- Rotating the KEK means re-wrapping 32-byte DEKs, not re-encrypting every field.
- Crypto-shredding: deleting a row's wrapped DEK makes its PII unrecoverable, including in
  backups. This is useful for erasure requests.
- With Vault transit, the KEK never leaves Vault, so the database and the app's memory dump are
  both useless without Vault access, which is separately audited.

`LocalKeyEnvelope` (KEK in process memory) exists for dev and tests. `VaultTransitEnvelope` is a
stub showing where the real one plugs in.

**AAD binds each ciphertext to its row and column.** Fields are sealed with AES-256-GCM and
additional data `"<id>|<column>"`. Someone with write access to the database can't copy Alice's
encrypted phone into Bob's row, or swap a name into the phone column, without decryption failing
(`TestCiphertextIsBoundToItsRow`).

**Phone search through an HMAC blind index.** Encrypted fields can't be queried. `phone_bidx` is
HMAC-SHA256 of the E.164-normalised phone, under a key separate from the KEK. Equal numbers give
equal indexes, so search is an indexed equality lookup.
- Normalisation happens before hashing (`NormalizePhone`), so `+1 (555) 123-4567` and
  `+15551234567` match.
- Trade-off: a blind index leaks equality, so an attacker with the database can see which rows
  share a phone number. It does not leak the number itself without the HMAC key. Only exact
  match is possible. No prefix, fuzzy or partial search, which I consider a feature for PII.
- Phone numbers have low entropy, so if the HMAC key leaks, they can be brute-forced. Hence a
  separate key, held in the key service like the KEK.

**Credentials: the method is a type, and the schema enforces it.** `Method` is `password`,
`passkey` or `totp`. Each method stores only what it needs:
- password: an argon2id PHC string (`$argon2id$v=19$m=65536,t=3,p=4$salt$hash`). The parameters
  travel with the hash, so they can be raised later without breaking old hashes.
- passkey: the WebAuthn credential ID and COSE public key. That is public material; the private key
  never leaves the authenticator.
- TOTP: the seed must be recoverable to compute codes, so it can't be hashed. It is envelope-encrypted
  like PII.

`Credential.Validate` and a database `CHECK` constraint both enforce "exactly the payload for the
method". The contract suite inserts a bad row with raw SQL to prove the database holds the rule on
its own. Partial unique indexes allow one password per username but several passkeys per user.

**argon2id, RFC 9106 parameters.** 64 MiB, t=3, p=4 by default. Verification compares in constant
time. Tests use cheap parameters through the same type.

**One pgx implementation for PostgreSQL and CockroachDB.** CockroachDB speaks the PostgreSQL wire
protocol, and this schema is valid in both, so one package and one migration serve both. The
difference that matters is concurrency. CockroachDB runs every transaction `SERIALIZABLE` and
returns SQLSTATE `40001` when the client must retry. `postgres.withRetry` re-runs the whole
statement with full-jitter backoff, up to 5 attempts, and returns any other error immediately.
PostgreSQL returns the same code at `SERIALIZABLE`, so the wrapper is correct for both. The retry
lives in the store layer, so callers never see a retryable error.

**SQLite through `modernc.org/sqlite`.** It is pure Go, so there is no cgo, cross-compiling is
trivial, and it runs under `-race`. Foreign keys are on, WAL is on, and `busy_timeout` is set.

**One contract suite.** `storetest.Run` is the specification of a store. SQLite, PostgreSQL and
CockroachDB all run the same six tests, and CI runs all three on every PR. A new dialect is
done when it passes the suite.

**Malformed ID means not found.** `Get("not-a-uuid")` returns `ErrNotFound`, not a database error.
Q2 relies on this to return one uniform 404 regardless of why the profile wasn't found.

### Trade-offs I accepted

- **Equality leakage** from the blind index, in exchange for indexed search. The alternative,
  decrypting and scanning, doesn't scale and still needs the plaintext in memory.
- **Usernames are plaintext.** Login needs an indexed lookup. If usernames are email addresses
  they are PII, and the same blind-index treatment applies.
- **No versioned migration runner.** `0001` is idempotent DDL and runs on open. That is fine for
  one migration and wrong for two.
- **A KMS round trip per read.** With Vault, every `Get` costs a network call to unwrap the DEK.
  For hot paths, a short-lived, size-bounded cache of unwrapped DEKs is the usual answer. I
  haven't built it because it trades away part of the memory-dump protection.

### With more time

- Vault transit for real, plus KEK rotation: prefix each wrapped DEK with its KEK version and
  re-wrap old ones in the background.
- Profile update and delete, with delete crypto-shredding the DEK.
- A rehash-on-login path: have `Verify` report when stored parameters are weaker than current ones.
- A versioned migration runner (goose or atlas), and separate DB roles in the migration with
  `GRANT`s.
- Credential lookups by passkey ID and by user, and WebAuthn sign-count tracking.
- Property-based tests for `NormalizePhone`, and fuzzing `Open` and `Verify`.

---

## Q2: REST API

*To be written in step Q2.*

## Q3: Identity provider connector

*To be written in step Q3.*
