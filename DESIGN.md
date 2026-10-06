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
both would make that separation a convention instead of a grant. SQLite has no roles and no
cross-file foreign keys, so there both tables share one file; SQLite is for dev and tests.

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
(`TestCiphertextIsBoundToItsRowAndColumn`).

**Phone search through an HMAC blind index.** Encrypted fields can't be queried. `phone_bidx` is
HMAC-SHA256 of the E.164-normalised phone, under a key separate from the KEK. Equal numbers give
equal indexes, so search is an indexed equality lookup.
- Normalisation happens before hashing (`NormalizePhone`), so `+1 (555) 123-4567` and
  `+15551234567` match.
- Trade-off: a blind index leaks equality, so an attacker with the database can see which rows
  share a phone number. It does not leak the number itself without the HMAC key. Only exact
  match is possible. No prefix, fuzzy or partial search, which I consider a feature for PII.
- Phone numbers have low entropy, so if the HMAC key leaks, they can be brute-forced. Hence a
  separate key of at least 32 bytes (`NewBlindIndex` refuses shorter ones), held in the key
  service like the KEK.
- The index column isn't authenticated, so `Search` checks each decrypted phone against the query.
  Pointing a row's index at someone else's number returns an error, not their PII.

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
time and bounds the parameters it reads from storage (`argon2.IDKey` panics on t=0 or p=0, and `m`
is an allocation size). Tests use cheap parameters through the same type.

**One pgx implementation for PostgreSQL and CockroachDB.** CockroachDB speaks the PostgreSQL wire
protocol, and this schema is valid in both, so one package and one migration serve both. The
difference that matters is concurrency. CockroachDB runs every transaction `SERIALIZABLE` and
returns SQLSTATE `40001` when the client must retry. `postgres.withRetry` re-runs the whole
statement with full-jitter backoff, up to 5 attempts, and returns any other error immediately.
PostgreSQL returns the same code at `SERIALIZABLE`, so the wrapper is correct for both. Writes go
through it in the store layer; reads are single statements that CockroachDB retries server-side
where it can. Wrapping reads too is a one-line change per query if contention shows up.

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

### Shape

```
request ─▶ request ID ─▶ recover ─▶ access log ─▶ ServeMux ─▶ auth + scope ─▶ rate limit ─▶ handler ─▶ audit ─▶ response
           (+16 KiB cap)                                       (per route)                    │
                                                                                profile.Repository (Q1)
```

### Decisions

**Two read endpoints, nothing else.** `GET /v1/profiles/{id}` and `POST /v1/profiles/search`.
The brief asks to search and retrieve; writes stay in the DAO. The server opens only the profile
store, so in production the API can connect under a role that can't read `user_credentials` (Q1's
two-store split pays off here). That needs migrations run as a separate step: today `Open` migrates on
start, which needs DDL rights on both tables.

**Search is a POST.** A phone number in a query string ends up in access logs, proxy logs, browser
history and `Referer` headers. In a body it ends up nowhere we don't control. The cost is that the
request isn't cacheable, which PII responses shouldn't be anyway (`Cache-Control: no-store` on every
response).

**One 404 for "doesn't exist" and "malformed".** Distinct answers would let a caller probe which IDs
exist and learn the ID format. `Repository.Get` returns `ErrNotFound` for anything that isn't a UUID
before touching the store (PostgreSQL would otherwise reject `%FF` as invalid UTF-8 with an error, a
500), so the handler has one path; a test compares the bodies byte for byte.

**OAuth2 bearer tokens with scopes, behind an interface.** Callers are services, so this is the
client-credentials model: the API checks a token and a scope (`profiles:read`) per route. The
`TokenVerifier` interface is the seam. The dev issuer mints opaque random tokens and keeps only their
SHA-256 hash, so lookups don't compare secrets byte by byte and a memory dump holds no usable tokens.
I didn't build a token endpoint: an unauthenticated endpoint that hands out credentials is attack
surface, even in dev. `-dev` prints one token at startup instead. Production would verify JWTs from
the organisation's authorization server or use introspection; the server refuses to start without
`-dev` until that exists.

**Rate limit per client, after auth.** A token bucket keyed by the authenticated client ID. That
means one noisy client can't starve the others, and the bucket map is bounded by the number of
registered clients, so there's nothing to evict. The gap: unauthenticated requests aren't limited.
Token checks are cheap, but in production an edge limiter (per IP, at the load balancer or gateway)
covers that layer.

**Audit every PII read, fail closed.** Each get and search records who (client, request ID), what
(action, profile IDs returned) and the outcome, never the PII itself. If the audit write fails the
request fails with 500 before any PII is written: an unaudited read is worse than an unavailable one
for this data. The `SlogAuditor` is a stand-in; real audit goes to an append-only store separate
from application logs.

**PII can't reach the logs, by three independent layers.**
- The access log records the route pattern (`GET /v1/profiles/{id}`), never the raw path, query or body.
- `Profile` and `Address` are `slog.LogValuer`s that render as `[REDACTED]`.
- The logger's `ReplaceAttr` redacts a deny-list of keys at any depth, as a backstop for a careless
  `log.Info("x", "phone", p)`.

A test sends a known phone number and asserts it appears nowhere in the log output. One path the
layers don't cover: a 500 logs its error text, so errors must not carry PII. The stores' and the
repository's errors don't; that is a convention to keep, not something the logger enforces.

**Errors map in one place, with fixed messages.** `errors.go` turns sentinels into statuses. The
client gets a code, a fixed message and the request ID, never the error text, which could carry
input or internals. 500s are logged in full with the request ID, so support can correlate.

**Input is bounded and strict.** 16 KiB body cap, unknown fields and trailing data rejected,
`page_size` 1..100, phone validated as E.164. Caller-supplied request IDs are accepted only if they
are short and `[A-Za-z0-9_-]`, so they can't inject into logs.

**Server hygiene.** Header, read, write and idle timeouts (slowloris), graceful shutdown on
SIGTERM so in-flight reads finish during a deploy.

### Trade-offs I accepted

- **Page tokens are the last ID, base64url-encoded, not encrypted or signed.** They contain no PII,
  and tampering with one only moves the cursor within the caller's own query. Signing them would
  stop clients from building cursors, which doesn't matter here.
- **A full page always returns a `next_page_token`**, so a result that's an exact multiple of the
  page size costs one extra empty request. Fetching `page_size+1` avoids it; not worth the code here.
- **Not-found audits don't record the requested ID.** Recording it would help spot enumeration.
  It's an easy change; I kept `SubjectIDs` meaning "profiles disclosed".

### With more time

- JWT verification against the real authorization server, and mTLS between services.
- An edge rate limiter per IP, and per-client quotas from configuration.
- Audit to an append-only, tamper-evident store, plus alerting on unusual read volumes per client.
- OpenAPI spec, metrics and tracing (request ID → trace ID).
- Attribute-based access: restrict which clients may read which tenants' profiles once there are tenants.

## Q3: Identity provider connector

*To be written in step Q3.*
