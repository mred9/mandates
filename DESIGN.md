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
exist and learn the ID format. `Repository.Get` returns `ErrNotFound` for anything that isn't a canonical
lowercase UUID before touching the store (PostgreSQL would otherwise reject `%FF` as invalid UTF-8 with an error, a
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

### Shape

```
caller ─▶ abc.New / xyz.New ─▶ provider.Client.Lookup
                                 │ validate (E.164 phone, name)        ─▶ ErrInvalidRequest, no call
                                 │ Do: breaker ─▶ attempt (timeout) ─▶ retry transient (jitter, Retry-After)
                                 │      └─ TokenCache ─▶ POST /auth (creds from Secrets), singleflight
                                 │      └─ POST /identity ─▶ 401? invalidate, re-auth, once more
                                 │ decode (vendor package) ─▶ normalise phone + country
                                 ▼
                              provider.Identity
```

### Decisions

**One client, thin adapters.** Authentication, token caching, retries, the breaker and status
mapping are the same for every vendor, so `provider.Client` does them once. A vendor package
supplies two functions: encode a request and decode a 200 answer (including its own way of saying
"no match"). ABC and XYZ are about 50 lines each, and adding vendor three means writing those two
functions and a fake. The alternative, each adapter owning its own retry and token logic, gives
two copies that drift.

**Tokens are cached, refreshed early, fetched once.** A token is reused until it is within
`RefreshBefore` (30s) of expiry, so a lookup never starts with a token about to die in flight.
When it does need a new one, concurrent lookups share a single `/auth` call (`singleflight`).
Without that, a burst after expiry sends one `/auth` per request, which is exactly the traffic
vendors throttle or lock accounts over. A missing `expires_in` assumes 5 minutes.

**A 401 means the token went stale, once.** The vendor may revoke a token before its stated
expiry. On a 401 from `/identity` the client drops that token and retries once with a fresh one.
A second 401 is a real authorization failure and is returned, not retried. `Invalidate(stale)`
only drops the token if it is still the cached one, so a slow request that gets a 401 can't throw
away the token another request has just fetched (`TestInvalidateKeepsANewerToken`).

**Retry only what can succeed next time.** Transient means a network error, an attempt that hit
its own timeout, 429, 502, 503 or 504. Everything else (400, 404, 401 after the refresh, other 5xx,
a malformed answer) returns at once: retrying a bad request just repeats it. Backoff is full
jitter (random up to `BackoffBase·2ⁿ`, capped at `BackoffMax`), so clients that failed together
don't retry together. A `Retry-After` from the vendor wins, but is capped at `BackoffMax`: a
vendor saying "come back in an hour" shouldn't hold a caller's request for an hour.

**Two deadlines.** Each attempt has its own `Timeout`, so one hung connection costs one attempt,
not the whole lookup. The timeout covers everything in the attempt (a token fetch, `/identity`,
a re-auth), which bounds an attempt's total time rather than each request's. The caller's context bounds everything: once it is done the client stops,
returns the caller's error rather than `ErrUnavailable`, and doesn't count it against the vendor.

**A circuit breaker per vendor.** After `BreakerThreshold` consecutive failed lookups the breaker
opens and lookups fail fast with `ErrCircuitOpen` for `BreakerCooldown`. Then exactly one probe
goes through: success closes the breaker, failure opens it again. This stops us adding load to a
vendor that is already down, and stops our callers waiting out timeouts and retries on every request.
Only `ErrUnavailable` counts as a failure. A "not found" or "bad request" is a healthy vendor
answering, and resets the count. The breaker counts lookups, not attempts, so one lookup that
retried three times is one failure.

**Secrets come from a secrets store, and go nowhere else.** Vendor credentials are read through
`Secrets` by name. `VaultSecrets` is the production shape: kv-v2 at `secret/data/idp/<vendor>`,
read with the service's own Vault identity, so credentials are never in config, env or the image,
and rotating them is a Vault write. `Credentials`, `Token`, `LookupRequest` and `Identity` all
redact themselves when logged. Errors carry the vendor, the operation and the status, never a
request, a response body, a token or a password: a JSON decode error, for instance, is replaced
with a fixed "malformed response" because it can quote the body. A test collects the errors from
the main failure paths (bad credentials, exhausted retries, bad request, rejected token, no match,
oversized answer) and checks none contains the password, a token, the phone or the name.

**Trust the vendor's transport, not its answers.**
- The base URL must be `https` (plain `http` only to a loopback host, for the fakes).
- The client follows no redirects, so credentials and tokens only ever go to the configured host.
- Answers are read up to 1 MiB; a longer one is cut off and fails as malformed.
- Each answer is normalised to our formats (E.164 phone, upper-case ISO 3166-1 alpha-2 country).
  One that won't normalise is rejected rather than passed on.

**Testing against fakes, both vendors.** `providertest.Fake` implements the protocol and its
failure modes (stale tokens, N×503, 429 with `Retry-After`, latency); each vendor's fake only
writes its own response body. Every resilience test runs against both vendors, so each adapter's
wiring is covered, not just the shared client. Each `decode` is also tested against literal JSON,
because a fake built from the adapter's own types would agree with a wrong field name.

**Where it plugs in.** The brief asks for no endpoint, so the connector is a library. The natural
caller is a verification or onboarding service: look up the person's identity at a vendor, compare
it with what they entered, and store the result through `profile.Repository`. That service, not
the connector, decides what to do with vendor PII: whether to keep it, and under which consent.
Calls should run in a background job or behind their own timeout, because a vendor lookup can take
several seconds under retries.

### Trade-offs I accepted

- **Retrying `POST /identity`.** It is a lookup, so it is safe to repeat, but some vendors bill
  per call: a retried request may be charged twice.
- **The shared token fetch runs under the first caller's context.** If that caller gives up, the
  callers waiting on the same fetch get its error too and retry. A detached context with its own
  timeout avoids that; for a token fetch that takes milliseconds it wasn't worth the code.
- **Bad credentials cost one `/auth` call per lookup.** `ErrUnauthorized` isn't a breaker
  failure, so a revoked password keeps trying. A real version would back off on auth failures,
  or alert, since only an operator can fix it.
- **No caching of identities.** Each lookup goes to the vendor. Caching vendor PII is a retention
  decision, not a performance one.
- **XYZ's schema is invented** (SPEC §3.2). If both vendors really share the brief's schema, the
  two adapters collapse into one with a vendor name.

### With more time

- Contract tests against each vendor's sandbox. The fakes encode my reading of the vendor; only
  the real API can prove it.
- Fallback or hedging across vendors (try ABC, fall back to XYZ when the breaker is open), and
  comparing their answers for fraud signals.
- `VaultSecrets` for real, re-reading credentials when the lease rotates and on an auth failure.
- A client-side rate limit matching each vendor's quota, so we get 429s less often.
- Metrics per vendor (latency, outcome, breaker state, retries) and alerting on the breaker opening.
- mTLS or request signing where a vendor supports it; libphonenumber and a real country list for
  normalisation.
