# SPEC

This spec covers the interfaces, data model and endpoints for the three parts of the exercise.
It is the contract I build against. DESIGN.md (written alongside the code) explains *why*;
this file says *what*.

Module path: `github.com/mred9/mandates`.
Toolchain: Go 1.27.1 (pinned through `go.mod`'s `go` directive and a local `mise.toml`).

---

## 0. Ground rules

- **TDD, Red → Green → Green.** For each unit: write a failing test and confirm it fails for the
  right reason (Red); write the least code that passes (Green); refactor with the suite still
  passing (Green). Contract suites are written before the implementations they exercise.
- **Scope.** Only what Q1–Q3 and the stated design decisions ask for. Anything else is listed under
  "Out of scope" below or marked `TODO:` in code with one sentence on what the real version does.
- **Errors.** Domain packages export sentinel errors. Callers wrap with `fmt.Errorf("...: %w", err)`.
  `internal/api/errors.go` is the only place sentinels become HTTP statuses.
- **Context.** Every function that does I/O takes `ctx context.Context` first.
- **Gates per step.** `go vet ./...` and `go test -race ./...` pass before each commit.
  One commit per step (SPEC, Q1, Q2, Q3).

### Layout

```
cmd/server/                 wiring, flags, graceful shutdown
internal/crypto/            envelope encryption (local key + Vault transit stub), blind index
internal/profile/           Profile model, Store interface, Repository (seals/unseals PII)
internal/credential/        Credential model, Store interface, argon2id hasher
internal/store/postgres/    pgx implementation of both stores (PostgreSQL + CockroachDB), migrations
internal/store/sqlite/      modernc.org/sqlite implementation of both stores, migrations
internal/store/storetest/   shared contract suites, run by every implementation
internal/api/               HTTP server, middleware, handlers, error mapping, token verifier stub
internal/provider/          IdentityProvider, Identity model, token cache, retry, breaker, secrets
internal/provider/abc/      ABC adapter + httptest fake
internal/provider/xyz/      XYZ adapter + httptest fake
```

`storetest` is the one addition to the requested layout: the contract suite has to live in an
importable non-`_test` package so both store packages can call it.

---

## 1. Q1: DAO

### 1.1 Crypto (`internal/crypto`)

```go
// Envelope wraps per-record data encryption keys (DEKs) with a key-encryption key (KEK)
// that never leaves the key service.
type Envelope interface {
    // GenerateDataKey returns a fresh 256-bit DEK and the same key wrapped by the KEK.
    GenerateDataKey(ctx context.Context) (plaintext, wrapped []byte, err error)
    // DecryptDataKey unwraps a DEK produced by GenerateDataKey.
    DecryptDataKey(ctx context.Context, wrapped []byte) ([]byte, error)
}

type LocalKeyEnvelope struct{ /* AES-256-GCM KEK held in memory; dev/test only */ }
type VaultTransitEnvelope struct{ /* TODO stub: transit/datakey/plaintext/<key> and transit/decrypt/<key> */ }

// Seal and Open encrypt one field with AES-256-GCM under a DEK.
// aad binds the ciphertext to its row and column so ciphertexts cannot be swapped between rows.
func Seal(dek, plaintext, aad []byte) ([]byte, error)
func Open(dek, ciphertext, aad []byte) ([]byte, error)

// BlindIndex computes HMAC-SHA256 over a normalised value with a key separate from the KEK.
type BlindIndex struct{ /* key */ }
func (b BlindIndex) Phone(e164 string) []byte
```

Wrapped DEKs carry a key-version prefix so the KEK can be rotated without rewriting rows at once.

Sentinels: `crypto.ErrDecrypt`.

### 1.2 Profile (`internal/profile`)

```go
type Address struct {
    StreetAddress, Locality, Region, PostalCode, Country string
}

type Profile struct {
    ID        string    // UUIDv7, server-assigned
    Name      string
    Phone     string    // E.164, normalised on write
    Address   Address
    CreatedAt time.Time
    UpdatedAt time.Time
}
// Profile and Address implement slog.LogValuer and log as redacted.

// Sealed is what a Store persists. Stores never see plaintext PII.
type Sealed struct {
    ID          string
    WrappedDEK  []byte
    Name        []byte // ciphertext
    Phone       []byte // ciphertext
    Address     []byte // ciphertext of JSON-encoded Address
    PhoneIndex  []byte // blind index
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

// Store is the ProfileStore from the brief.
type Store interface {
    Create(ctx context.Context, p Sealed) error
    Get(ctx context.Context, id string) (Sealed, error)
    Update(ctx context.Context, p Sealed) error
    Delete(ctx context.Context, id string) error
    // FindByPhoneIndex returns up to limit rows with id > after, ordered by id.
    FindByPhoneIndex(ctx context.Context, index []byte, after string, limit int) ([]Sealed, error)
}

// Repository is the DAO callers use: plaintext Profile in, plaintext Profile out.
type Repository struct{ /* Store, crypto.Envelope, crypto.BlindIndex, clock, id generator */ }
func (r *Repository) Create(ctx context.Context, p Profile) (Profile, error)
func (r *Repository) Get(ctx context.Context, id string) (Profile, error)
func (r *Repository) Update(ctx context.Context, p Profile) (Profile, error)
func (r *Repository) Delete(ctx context.Context, id string) error
func (r *Repository) Search(ctx context.Context, q Query) (Page, error)

type Query struct {
    Phone     string // required; exact match through the blind index
    Name      string // optional; exact match after normalisation, applied post-decrypt
    PageSize  int    // default 20, max 100
    PageToken string // opaque, contains no PII
}
type Page struct {
    Items         []Profile
    NextPageToken string
}
```

Sentinels: `profile.ErrNotFound`, `profile.ErrInvalid`, `profile.ErrConflict`.

### 1.3 Credential (`internal/credential`)

```go
type Method string
const (
    MethodPassword Method = "password"
    MethodPasskey  Method = "passkey"
    MethodTOTP     Method = "totp"
)

type Credential struct {
    ID        string
    UserID    string // profile ID
    Username  string // lowercased, trimmed
    Method    Method
    Password  *PasswordData // set iff Method == MethodPassword
    Passkey   *PasskeyData  // set iff Method == MethodPasskey
    TOTP      *TOTPData     // set iff Method == MethodTOTP
    CreatedAt time.Time
}

type PasswordData struct{ Hash string }            // argon2id PHC string; never the password
type PasskeyData  struct{ CredentialID, PublicKey []byte; SignCount uint32 } // public material only
type TOTPData     struct{ WrappedDEK, SecretCiphertext []byte } // must be recoverable to verify, so encrypted, not hashed

// Store is the CredentialStore from the brief.
type Store interface {
    Create(ctx context.Context, c Credential) error
    Get(ctx context.Context, id string) (Credential, error)
    FindByUsername(ctx context.Context, username string, m Method) ([]Credential, error)
    FindByPasskeyID(ctx context.Context, credentialID []byte) (Credential, error)
    ListByUser(ctx context.Context, userID string) ([]Credential, error)
    Delete(ctx context.Context, id string) error
}

// PasswordHasher hashes and verifies with argon2id (golang.org/x/crypto/argon2).
type PasswordHasher interface {
    Hash(password string) (string, error)
    // Verify compares in constant time. needsRehash is true when the stored
    // parameters are weaker than the current ones.
    Verify(password, encoded string) (ok, needsRehash bool, err error)
}
```

Default argon2id parameters: m=64 MiB, t=3, p=4, 16-byte salt, 32-byte key (RFC 9106 second
recommended option). Tests inject cheap parameters.

`Credential.Validate()` enforces that exactly the payload matching `Method` is set.

Sentinels: `credential.ErrNotFound`, `credential.ErrInvalid`, `credential.ErrConflict`.

### 1.4 Data model

Same logical schema in both dialects. Postgres/CockroachDB types shown; SQLite uses `TEXT`/`BLOB`/`INTEGER`
with the same constraints.

```sql
CREATE TABLE user_profiles (
    id          UUID PRIMARY KEY,
    wrapped_dek BYTEA NOT NULL,
    name_ct     BYTEA NOT NULL,
    phone_ct    BYTEA NOT NULL,
    address_ct  BYTEA NOT NULL,
    phone_bidx  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX user_profiles_phone_bidx ON user_profiles (phone_bidx, id);

CREATE TABLE user_credentials (
    id                    UUID PRIMARY KEY,
    user_id               UUID NOT NULL REFERENCES user_profiles (id) ON DELETE CASCADE,
    username              TEXT NOT NULL,
    method                TEXT NOT NULL CHECK (method IN ('password','passkey','totp')),
    password_hash         TEXT,
    passkey_credential_id BYTEA,
    passkey_public_key    BYTEA,
    passkey_sign_count    BIGINT,
    totp_wrapped_dek      BYTEA,
    totp_secret_ct        BYTEA,
    created_at            TIMESTAMPTZ NOT NULL,
    CHECK ( (method = 'password' AND password_hash IS NOT NULL AND passkey_credential_id IS NULL AND totp_secret_ct IS NULL)
         OR (method = 'passkey'  AND passkey_credential_id IS NOT NULL AND passkey_public_key IS NOT NULL AND password_hash IS NULL AND totp_secret_ct IS NULL)
         OR (method = 'totp'     AND totp_secret_ct IS NOT NULL AND totp_wrapped_dek IS NOT NULL AND password_hash IS NULL AND passkey_credential_id IS NULL) )
);
CREATE UNIQUE INDEX user_credentials_password_username ON user_credentials (username) WHERE method = 'password';
CREATE UNIQUE INDEX user_credentials_passkey_id ON user_credentials (passkey_credential_id) WHERE method = 'passkey';
CREATE INDEX user_credentials_user ON user_credentials (user_id);
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL);
```

Separate tables so they can sit under different grants (the API's DB role gets no access to
`user_credentials`). Migrations are embedded `.sql` files per dialect, applied by a small runner in
each store package. PostgreSQL and CockroachDB share one migration set because this schema is
valid in both; the directory is still per dialect so they can diverge.

### 1.5 Stores

- `postgres.New(ctx, pool *pgxpool.Pool, opts...)` returns a type implementing both
  `profile.Store` and `credential.Store`. All writes go through `runTx`, which retries the whole
  transaction on SQLSTATE `40001` (CockroachDB restart, Postgres serialization failure) with
  bounded exponential backoff. Unique violation `23505` maps to `ErrConflict`.
- `sqlite.Open(ctx, dsn)` returns the same pair over `database/sql` + `modernc.org/sqlite`, with
  `foreign_keys=ON`, WAL, `busy_timeout`.
- `storetest.RunProfileStore(t, newStore func(t) profile.Store)` and
  `storetest.RunCredentialStore(t, ...)` are the contract suites.
- SQLite runs in every `go test`. Postgres and CockroachDB run when `TEST_POSTGRES_DSN` /
  `TEST_COCKROACH_DSN` are set (a `docker-compose.yml` provides both) and skip otherwise. The
  Docker daemon is not running on the build machine, so these will be reported as skipped.

---

## 2. Q2: REST API

### 2.1 Endpoints

| Method | Path | Scope | Notes |
|---|---|---|---|
| `GET`  | `/v1/profiles/{id}` | `profiles:read` | 200 profile, or uniform 404 |
| `POST` | `/v1/profiles/search` | `profiles:read` | PII in body only; 200 with possibly empty `items` |
| `POST` | `/oauth2/token` | none | **dev stub only** (`-dev` flag): client credentials grant, HTTP Basic client auth |
| `GET`  | `/healthz` | none | liveness |

Routing uses `net/http.ServeMux` method-and-path patterns. No chi.

**Profile response**

```json
{
  "id": "0192...", "name": "Ada Lovelace", "phone": "+15551234567",
  "address": {"street_address": "...", "locality": "...", "region": "...", "postal_code": "...", "country": "GB"},
  "created_at": "2026-10-06T00:00:00Z", "updated_at": "2026-10-06T00:00:00Z"
}
```

**Search request / response**

```json
{"phone": "+15551234567", "name": "Ada Lovelace", "page_size": 20, "page_token": ""}
{"items": [ /* profiles */ ], "next_page_token": "..."}
```

`page_token` is an opaque base64url keyset cursor (last returned ID). It contains no PII.

**Error envelope** (every non-2xx)

```json
{"error": {"code": "not_found", "message": "resource not found", "request_id": "..."}}
```

| Sentinel | Status | code |
|---|---|---|
| `profile.ErrNotFound`, malformed ID | 404 | `not_found` |
| `profile.ErrInvalid`, bad JSON, unknown fields | 400 | `invalid_request` |
| `api.ErrUnauthenticated` | 401 + `WWW-Authenticate: Bearer` | `unauthenticated` |
| `api.ErrForbidden` (missing scope) | 403 | `insufficient_scope` |
| `api.ErrRateLimited` | 429 + `Retry-After` | `rate_limited` |
| anything else | 500 | `internal` (details logged, not returned) |

Malformed and non-existent IDs return byte-identical 404 bodies (apart from `request_id`).

### 2.2 Auth

```go
type Principal struct {
    ClientID string
    Scopes   []string
}
type TokenVerifier interface {
    Verify(ctx context.Context, bearer string) (Principal, error) // ErrUnauthenticated on any failure
}
```

Dev implementation: an in-memory issuer that mints random opaque tokens (32 bytes, base64url)
with scopes and expiry, and verifies them with constant-time lookup. `TODO:` production verifies
JWTs from the real authorization server (JWKS, `iss`, `aud`, `exp`, `scope`) or uses RFC 7662
introspection.

### 2.3 Middleware chain (outer → inner)

1. **Request ID**: accept `X-Request-ID` if it is ≤64 chars of `[A-Za-z0-9-_]`, else generate; echo it; put it in context.
2. **Recover**: panic → 500 with the error envelope.
3. **Access log**: slog, method, route pattern (not raw path), status, duration, request ID, client ID. No bodies, no query strings.
4. **Auth**: bearer → `Principal` in context; per-route scope check.
5. **Rate limit**: token bucket per `ClientID` (`golang.org/x/time/rate`), idle buckets evicted.
6. **Handler.** Writes an audit event for every PII read before writing the response.

### 2.4 Audit

```go
type AuditEvent struct {
    Time      time.Time
    RequestID string
    ClientID  string
    Action    string   // "profile.get", "profile.search"
    SubjectIDs []string // profile IDs returned; never PII
    Outcome   string   // "returned", "not_found", "empty"
}
type Auditor interface { Record(ctx context.Context, e AuditEvent) error }
```

Slog implementation writes to a dedicated logger. If `Record` fails the handler returns 500 and
no PII (fail closed).

### 2.5 Logging and redaction

- `slog.JSONHandler` wrapped with `ReplaceAttr` that redacts a deny-list of keys
  (`name`, `phone`, `address`, `password`, `token`, `authorization`, `secret`, …) at any depth.
- `profile.Profile` and `profile.Address` implement `slog.LogValuer` and render as `[REDACTED]`
  apart from `id`.
- Test: a request whose body contains a known phone number produces log output that does not
  contain it.

### 2.6 Server

`cmd/server` flags: `-addr`, `-db` (`sqlite|postgres`), `-dsn`, `-dev`, `-rate`, `-burst`.
Server sets `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, a request body limit
(`http.MaxBytesReader`, 16 KiB), and shuts down gracefully on SIGINT/SIGTERM.

---

## 3. Q3: Identity provider connector

### 3.1 Interfaces (`internal/provider`)

```go
type Address struct{ StreetAddress, Locality, Region, PostalCode, Country string }
type Identity struct {
    Provider string
    Name     string
    Phone    string
    Address  Address
}
type LookupRequest struct{ Phone, Name string }

type IdentityProvider interface {
    Name() string
    Lookup(ctx context.Context, req LookupRequest) (Identity, error)
}

type Credentials struct{ Username, Password string }
type Secrets interface {
    VendorCredentials(ctx context.Context, vendor string) (Credentials, error)
}
// StaticSecrets (dev/tests) and VaultSecrets (TODO stub: reads kv-v2 secret/data/idp/<vendor>).

type Token struct{ AccessToken string; ExpiresAt time.Time }
type TokenFetcher func(ctx context.Context) (Token, error)

// TokenCache returns a cached token, refreshing it when it is within RefreshBefore of
// expiry. Concurrent callers share one in-flight refresh (singleflight).
type TokenCache struct{ /* fetcher, clock, refreshBefore */ }
func (c *TokenCache) Token(ctx context.Context) (string, error)
func (c *TokenCache) Invalidate()

type Breaker struct{ /* closed → open after N consecutive failures → half-open after cooldown */ }
func (b *Breaker) Allow() error   // ErrCircuitOpen
func (b *Breaker) Record(err error)

type VendorConfig struct {
    BaseURL          string
    Timeout          time.Duration // per HTTP attempt
    MaxAttempts      int
    BackoffBase      time.Duration
    BackoffMax       time.Duration
    BreakerThreshold int
    BreakerCooldown  time.Duration
    RefreshBefore    time.Duration
    SecretName       string
}

// Do runs one vendor call with timeout, retry on transient failures only, and breaker.
func Do(ctx context.Context, cfg VendorConfig, b *Breaker, call func(ctx context.Context) error) error
```

Transient means: network error, timeout of a single attempt (not the parent context), 429,
502, 503, 504. `Retry-After` is honoured up to `BackoffMax`. Everything else is permanent.
A 401 from `/identity` invalidates the token cache and retries once with a fresh token.

Sentinels: `provider.ErrNotFound`, `provider.ErrInvalidRequest`, `provider.ErrUnauthorized`,
`provider.ErrUnavailable`, `provider.ErrCircuitOpen`.

### 3.2 Vendor schemas

The brief gives one shape for both vendors. To show the adapter boundary doing real work I
assume ABC uses it verbatim and XYZ differs:

| | ABC | XYZ (assumed) |
|---|---|---|
| `POST /auth` request | `{"username","password"}` | same |
| `POST /auth` response | `{"access_token","expires_in"}` | `{"access_token","expires_in"}` |
| `POST /identity` request | `{"phone","name"}` | same |
| `POST /identity` response | `{"name","phone","address":{"street_address","locality","region","postal_code","country"}}` | `{"data":{"full_name","phone_number","address":{"line1","city","state","zip","country_code"}}}` |
| not found | 404 | 200 with `{"data":null}` |

`expires_in` missing → assume 5 minutes (configurable). Both adapters normalise phone to E.164 and
country to ISO 3166-1 alpha-2 upper case.

### 3.3 Fakes

`abc/fake.go` and `xyz/fake.go` expose `httptest.Server`-backed fakes with knobs: fixed identities,
token TTL, counters for `/auth` calls, and injectable failures (N× 503, 429 with `Retry-After`,
401 on stale token, latency). They are used by adapter tests and the shared connector tests.

The connector is a library. It is not exposed over HTTP by `cmd/server` because the brief does not
ask for an endpoint; DESIGN.md describes where it would plug in.

---

## 4. Out of scope

- Profile/credential write endpoints in the API (the DAO supports writes; the brief asks the API for search and retrieve).
- Login, passkey ceremonies, TOTP verification (the DAO stores the material; flows are not asked for).
- A real authorization server, real Vault, KMS, real vendor endpoints.
- Fuzzy or partial PII search (incompatible with blind indexing; see DESIGN.md).
- Deployment manifests, metrics/tracing exporters.

## 5. Dependencies

| Module | Why |
|---|---|
| `github.com/jackc/pgx/v5` | PostgreSQL/CockroachDB driver and pool |
| `modernc.org/sqlite` | pure-Go SQLite, no cgo, works under `-race` |
| `golang.org/x/crypto` | argon2id |
| `golang.org/x/time` | token bucket rate limiter |
| `golang.org/x/sync` | singleflight |
| `github.com/google/uuid` | UUIDv7 IDs |

No test framework beyond `testing`; no mocking library.
