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
  Each step (Q1, Q2, Q3) is a GitHub issue and a PR to `main`, with commits per layer and CI
  (`.github/workflows/ci.yml`) running the suite on all three databases.

### Layout

```
cmd/server/                 wiring, flags, graceful shutdown
internal/crypto/            envelope encryption (local key + Vault transit stub), blind index
internal/profile/           Profile model, Store interface, Repository (seals/unseals PII)
internal/credential/        Credential model, Store interface, argon2id hasher
internal/store/postgres/    pgx implementation of both stores (PostgreSQL + CockroachDB), migrations
internal/store/sqlite/      modernc.org/sqlite implementation of both stores, migrations
internal/store/storetest/   the shared contract suite, run by every implementation
internal/api/               HTTP handler, middleware, error mapping, audit, redacting logger, dev token issuer
internal/provider/          IdentityProvider, Identity model, Client, token cache, retry, breaker, secrets
internal/provider/providertest/  the shared httptest vendor fake
internal/provider/abc/      ABC adapter + its fake
internal/provider/xyz/      XYZ adapter + its fake
```

`storetest` and `providertest` are the additions to the layout I first planned: shared test code has to
live in an importable non-`_test` package so several packages can use it.

---

## 1. Q1: DAO

Kept deliberately small for a 30-minute walkthrough; DESIGN.md §1 covers what a full version adds.

### 1.1 Crypto (`internal/crypto`)

```go
type Envelope interface {
    GenerateDataKey(ctx context.Context) (plaintext, wrapped []byte, err error)
    DecryptDataKey(ctx context.Context, wrapped []byte) ([]byte, error)
}
type LocalKeyEnvelope struct{ /* KEK in memory; dev/test only */ }
type VaultTransitEnvelope struct{ /* TODO stub */ }

func Seal(key, plaintext, aad []byte) ([]byte, error) // AES-256-GCM, nonce||ciphertext
func Open(key, sealed, aad []byte) ([]byte, error)    // any failure → ErrDecrypt

type BlindIndex struct{ /* HMAC-SHA256 key, separate from the KEK */ }
func NewBlindIndex(key []byte) (*BlindIndex, error) // key ≥ 32 bytes
func (b *BlindIndex) Sum(value string) []byte
```

### 1.2 Profile (`internal/profile`)

```go
type Address struct{ StreetAddress, Locality, Region, PostalCode, Country string }
type Profile struct {
    ID        string // UUIDv7
    Name      string
    Phone     string // E.164
    Address   Address
    CreatedAt time.Time
} // implements slog.LogValuer: logs only the ID

type Sealed struct { // what a Store persists: ciphertext only
    ID                                   string
    WrappedDEK, Name, Phone, Address     []byte
    PhoneIndex                           []byte
    CreatedAt                            time.Time
}

type Store interface { // the ProfileStore
    Create(ctx context.Context, s Sealed) error
    Get(ctx context.Context, id string) (Sealed, error)
    FindByPhoneIndex(ctx context.Context, index []byte, after string, limit int) ([]Sealed, error)
}

func NewRepository(s Store, env crypto.Envelope, index *crypto.BlindIndex) *Repository
func (r *Repository) Create(ctx context.Context, p Profile) (Profile, error)
func (r *Repository) Get(ctx context.Context, id string) (Profile, error)
// Search: limit 1..100, after "" or a UUID; each result's decrypted phone must equal the query.
func (r *Repository) Search(ctx context.Context, phone, after string, limit int) ([]Profile, error)
func NormalizePhone(s string) (string, error)
```

Each row gets its own DEK; each field is sealed with AAD `"<id>|<column>"`.
Sentinels: `ErrNotFound`, `ErrInvalid`, `ErrConflict`.

### 1.3 Credential (`internal/credential`)

```go
type Method string // "password" | "passkey" | "totp"
type Credential struct {
    ID, UserID, Username string
    Method               Method
    PasswordHash         string // argon2id PHC string
    PasskeyID, PasskeyPublicKey []byte
    TOTPWrappedDEK, TOTPSecret  []byte // TOTPSecret is ciphertext
    CreatedAt            time.Time
}
func (c Credential) Validate() error // exactly the payload for Method

type Store interface { // the CredentialStore
    Create(ctx context.Context, c Credential) error
    FindByUsername(ctx context.Context, username string, m Method) ([]Credential, error)
}

type Argon2id struct{ Memory, Time uint32; Threads uint8 }
var DefaultArgon2id = Argon2id{Memory: 64 * 1024, Time: 3, Threads: 4} // RFC 9106
func (a Argon2id) Hash(password string) (string, error)
func (Argon2id) Verify(password, encoded string) (bool, error) // constant-time compare
```

Sentinels: `ErrInvalid`, `ErrConflict`. `Credential` implements `slog.LogValuer` (ID and method only).

### 1.4 Data model

`internal/store/postgres/migrations/0001_init.up.sql` (PostgreSQL and CockroachDB) and
`internal/store/sqlite/migrations/0001_init.up.sql` (same schema, SQLite types), each with a
`down` file.

- `user_profiles(id, wrapped_dek, name_ct, phone_ct, address_ct, phone_bidx, created_at)`,
  index `(phone_bidx, id)` for search plus keyset paging.
- `user_credentials(id, user_id → user_profiles ON DELETE CASCADE, username, method,
  password_hash, passkey_credential_id, passkey_public_key, totp_wrapped_dek, totp_secret_ct, created_at)`
  with a CHECK that only the method's columns are set, a partial unique index on `username`
  for passwords, and a partial unique index on `passkey_credential_id` for passkeys.

### 1.5 Stores

- Each dialect exposes `Open` (`postgres.Open(ctx, dsn)`, `sqlite.Open(ctx, path)`) plus `NewProfileStore` and `NewCredentialStore`:
  two types, so each can be handed a connection under a different database role.
- `postgres.withRetry` re-runs a whole statement on SQLSTATE `40001` (up to 5 attempts, full
  jitter). `23505` → `ErrConflict`; a malformed UUID (`22P02`) → `ErrNotFound`.
- `storetest.Run(t, func(t) Harness)` is the one contract suite; SQLite always runs it,
  PostgreSQL and CockroachDB run it when `TEST_POSTGRES_DSN` / `TEST_COCKROACH_DSN` are set.

---

## 2. Q2: REST API

### 2.1 Endpoints

| Method | Path | Scope | Notes |
|---|---|---|---|
| `GET`  | `/v1/profiles/{id}` | `profiles:read` | 200 profile, or uniform 404 |
| `POST` | `/v1/profiles/search` | `profiles:read` | phone in the body only; 200 with possibly empty `items` |
| `GET`  | `/healthz` | none | liveness |

Routing uses `net/http.ServeMux` method-and-path patterns. Any other path returns the 404 envelope.
Every response sets `Cache-Control: no-store`.

**Profile response**

```json
{
  "id": "0192...", "name": "Ada Lovelace", "phone": "+15551234567",
  "address": {"street_address": "...", "locality": "...", "region": "...", "postal_code": "...", "country": "GB"},
  "created_at": "2026-10-06T00:00:00Z"
}
```

**Search request / response**

```json
{"phone": "+15551234567", "page_size": 20, "page_token": ""}
{"items": [ /* profiles */ ], "next_page_token": "..."}
```

`page_size` omitted or 0 means 20; otherwise it must be 1..100. Unknown fields and trailing data are rejected.
`page_token` is base64url of the last returned ID (a UUID, no PII); it is present when the page
was full.

**Error envelope** (every 4xx and 5xx; messages are fixed per code)

```json
{"error": {"code": "not_found", "message": "resource not found", "request_id": "..."}}
```

| Error | Status | code |
|---|---|---|
| `profile.ErrNotFound` (unknown or malformed ID), unknown route | 404 | `not_found` |
| `profile.ErrInvalid`, `api.ErrInvalidRequest` (bad JSON, unknown fields, body over 16 KiB, bad `page_token`) | 400 | `invalid_request` |
| `api.ErrUnauthenticated` | 401 + `WWW-Authenticate: Bearer` | `unauthenticated` |
| `api.ErrForbidden` (missing scope) | 403 | `insufficient_scope` |
| `api.ErrRateLimited` | 429 + `Retry-After` | `rate_limited` |
| anything else, including a panic | 500 | `internal` (details logged, not returned) |

Malformed and non-existent IDs return byte-identical 404 bodies (apart from `request_id`):
`profile.Repository.Get` returns `ErrNotFound` for anything that isn't a canonical lowercase UUID
without calling the store; `page_token` must decode to one too.
`internal/api/errors.go` is the only place errors become statuses.

### 2.2 Auth

```go
type Principal struct{ ClientID string; Scopes []string }
type TokenVerifier interface {
    Verify(ctx context.Context, bearer string) (Principal, error) // ErrUnauthenticated on any failure
}
func NewDevTokens() *DevTokens
func (d *DevTokens) Mint(clientID string, scopes []string, ttl time.Duration) (string, error)
```

`DevTokens` mints random opaque tokens (32 bytes, base64url) and stores them by SHA-256 with
scopes and expiry. There is no token endpoint: `cmd/server -dev` mints one `profiles:read` token
at startup and prints it to stderr. `TODO:` production verifies JWTs from the real authorization
server (JWKS, `iss`, `aud`, `exp`, `scope`) or uses RFC 7662 introspection.

### 2.3 Middleware chain (outer → inner)

1. **Request ID**: accept `X-Request-ID` if it matches `[A-Za-z0-9_-]{1,64}`, else generate; echo it; put it in context. Also caps the body at 16 KiB (`http.MaxBytesReader`).
2. **Access log**: method, route pattern (not raw path), status, duration, request ID, client ID. No bodies, no query strings.
3. **Recover**: panic → 500 with the error envelope. Inside the access log, so a panicked request is logged with its 500.
4. **Auth** (per route): bearer → `Principal`; scope check.
5. **Rate limit** (per route): token bucket per `ClientID` (`golang.org/x/time/rate`). Keys are authenticated client IDs, so buckets are not evicted.
6. **Handler.** Records an audit event for every PII read before writing the response.

### 2.4 Audit

```go
type AuditEvent struct {
    Time       time.Time
    RequestID  string
    ClientID   string
    Action     string   // "profile.get", "profile.search"
    SubjectIDs []string // profile IDs returned; never PII
    Outcome    string   // "returned", "not_found", "empty"
}
type Auditor interface { Record(ctx context.Context, e AuditEvent) error }
```

`SlogAuditor` writes to a dedicated logger (`log=audit`). If `Record` fails the handler returns
500 and no PII (fail closed).

### 2.5 Logging and redaction

- `api.NewLogger`: `slog.JSONHandler` with a `ReplaceAttr` that redacts a deny-list of keys
  (`name`, `phone`, `address`, `password`, `token`, `authorization`, `secret`, …), matching an attribute's
  own key or any enclosing group's key. It matches keys, not values.
- `profile.Profile` and `profile.Address` implement `slog.LogValuer` (a profile logs only its ID).
- Tested: requests carrying a known phone number produce logs that contain neither it nor the name.

### 2.6 Server

`cmd/server` flags: `-addr`, `-db` (`sqlite|postgres`), `-dsn`, `-dev`, `-rate`, `-burst`. Keys come
from `MANDATES_KEK` and `MANDATES_INDEX_KEY` (base64, 32 bytes); with `-dev`, missing ones are
generated for the run. Only `-dev` starts, since the production verifier and envelope are stubs.
The server opens only the profile store and sets `ReadHeaderTimeout`, `ReadTimeout`,
`WriteTimeout`, `IdleTimeout`, and shuts down gracefully on SIGINT/SIGTERM.

---

## 3. Q3: Identity provider connector

### 3.1 Interfaces (`internal/provider`)

```go
type Address struct{ StreetAddress, Locality, Region, PostalCode, Country string }
type Identity struct {
    Provider string
    Name     string
    Phone    string // E.164
    Address  Address
} // implements slog.LogValuer: logs only the provider
type LookupRequest struct{ Phone, Name string } // redacts itself in logs

type IdentityProvider interface {
    Name() string
    Lookup(ctx context.Context, req LookupRequest) (Identity, error)
}

type Credentials struct{ Username, Password string } // redacts itself in logs
type Secrets interface {
    VendorCredentials(ctx context.Context, vendor string) (Credentials, error)
}
// StaticSecrets (map, dev/tests) and VaultSecrets (TODO stub: kv-v2 secret/data/idp/<vendor>).

type Token struct{ AccessToken string; ExpiresAt time.Time } // redacts itself in logs
type TokenFetcher func(ctx context.Context) (Token, error)

// Refreshes when within refreshBefore of expiry; concurrent callers share one fetch (singleflight).
func NewTokenCache(fetch TokenFetcher, refreshBefore time.Duration, now func() time.Time) *TokenCache
func (c *TokenCache) Token(ctx context.Context) (string, error)
func (c *TokenCache) Invalidate(stale string) // only if stale is still the cached token

// closed → open after threshold consecutive failures → one half-open probe after cooldown.
func NewBreaker(threshold int, cooldown time.Duration, now func() time.Time) *Breaker
func (b *Breaker) Allow() error   // ErrCircuitOpen
func (b *Breaker) Record(err error) // ErrUnavailable is a failure; the caller's context error is neither

type VendorConfig struct {
    BaseURL          string        // https, or http to a loopback host (tests)
    Timeout          time.Duration // per attempt, covering its /auth, /identity and any re-auth; 5s
    MaxAttempts      int           // 3
    BackoffBase      time.Duration // 100ms, full jitter
    BackoffMax       time.Duration // 2s; also caps Retry-After
    BreakerThreshold int           // 5
    BreakerCooldown  time.Duration // 30s
    RefreshBefore    time.Duration // 30s
    DefaultTokenTTL  time.Duration // 5m, when /auth omits expires_in
    SecretName       string        // the vendor name
    Now              func() time.Time
}

// Do runs one call through the breaker with a timeout per attempt and retries on transient failures.
func Do(ctx context.Context, cfg VendorConfig, b *Breaker, call func(ctx context.Context) error) error

// Client is the IdentityProvider. A vendor package supplies only enc and dec.
type Encoder func(LookupRequest) any
type Decoder func(body []byte) (Identity, error) // or ErrNotFound
// notFound is the status the vendor says "no match" with, or 0 if it says so in a 200 body.
func New(vendor string, notFound int, cfg VendorConfig, s Secrets, enc Encoder, dec Decoder) (*Client, error)
```

`abc.New(cfg, secrets)` and `xyz.New(cfg, secrets)` return a `*provider.Client`.

**Lookup.**
1. Validate the request: phone must normalise to E.164 (`profile.NormalizePhone`) and the name must be non-empty. Otherwise return `ErrInvalidRequest` without a vendor call.
2. Get a token: cached, or fetched from `POST /auth` with credentials from `Secrets`.
3. Call `POST /identity`. A 401 invalidates the token and retries with a fresh one, once per lookup (across retry attempts).
4. Decode the response, normalise the phone to E.164 and the country to upper-case ISO 3166-1 alpha-2, and set `Provider`.

| Vendor status | Result | Retried |
|---|---|---|
| 200 | decoded identity | |
| 401 (after the one refresh), 403 | `ErrUnauthorized` | no |
| the vendor's `notFound` status (ABC: 404) | `ErrNotFound` | no |
| 400, 422 | `ErrInvalidRequest` | no |
| 429, 502, 503, 504, network error, attempt timeout | `ErrUnavailable` once attempts run out | yes; `Retry-After` honoured up to `BackoffMax` |
| other (including a 404 from XYZ), malformed or over-1-MiB body | `ErrUnavailable` | no |
| caller's context done | the context error | no |
| breaker open | `ErrCircuitOpen` | no vendor call |

`/auth` uses the same mapping, so bad credentials are an `ErrUnauthorized` and are never retried,
except that a 400 or 422 from `/auth` is `ErrUnavailable`: it isn't the lookup's "bad input". (A 404 from
`/auth` is never "no match": it falls under "other".)
The client follows no redirects. Errors carry the vendor, operation and status, never a request,
a response body, a token, credentials or the secret store's error text.

Sentinels: `ErrNotFound`, `ErrInvalidRequest`, `ErrUnauthorized`, `ErrUnavailable`, `ErrCircuitOpen`.

### 3.2 Vendor schemas

The brief names the vendors "ABC, or XYC"; this repo calls the second one XYZ. The brief gives one
shape for both vendors. To show the adapter boundary doing real work I assume ABC uses it verbatim
and XYZ differs:

| | ABC | XYZ (assumed) |
|---|---|---|
| `POST /auth` request | `{"username","password"}` | same |
| `POST /auth` response | `{"access_token","expires_in"}` | same |
| `POST /identity` request | `{"phone","name"}` | same |
| `POST /identity` response | `{"name","phone","address":{"street_address","locality","region","postal_code","country"}}` | `{"data":{"full_name","phone_number","address":{"line1","city","state","zip","country_code"}}}` |
| not found | 404 | 200 with `{"data":null}` (a body with no `data` field is malformed; a 404 is `ErrUnavailable`) |

### 3.3 Fakes

`providertest.Fake` is one `httptest.Server` implementing the protocol. Its knobs are token TTL
(or no `expires_in`), N injected statuses per endpoint (with `Retry-After`), latency on `/identity` and `/auth`,
and counters for both endpoints. `abc.NewFake` and `xyz.NewFake` supply only their vendor's
`/identity` body and not-found rule. The resilience tests run against both vendors; each vendor's
`decode` is also tested against literal JSON, so a field-name mistake shared by an adapter and its
fake still fails.

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
