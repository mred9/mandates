# AI log

Running log of what the assistant (Claude Code) produced at each step, the assumptions it made,
and what a reviewer should double-check. Edit freely.

---

## Step 0: SPEC.md

**Produced**
- `SPEC.md`: interfaces, data model, endpoints, error mapping, vendor schemas, out-of-scope list, dependency list.
- `AI_LOG.md` (this file), `.gitignore`.

**Assumptions**
- Module path `github.com/mred9/mandates`, matching the GitHub remote.
- Go 1.27.1, pinned in `mise.toml`.
- Added `internal/store/storetest` to the requested layout: the shared contract suite has to be an importable package so both store packages can run it.
- Idiomatic names: the brief's `ProfileStore`/`CredentialStore` are `profile.Store` and `credential.Store`.
- Stores persist only sealed (encrypted) profile records; encryption lives in `profile.Repository`, so the dialect code never handles plaintext PII and the crypto is written once.
- Search requires `phone` (blind-indexed); `name` is an optional exact-match filter applied after decryption. Only phone gets a blind index, per the brief.
- TOTP secrets are envelope-encrypted, not hashed, because the verifier needs the raw secret.
- Username uniqueness is enforced only for password credentials (partial unique index); passkeys are unique by credential ID. A user can hold several credentials.
- PostgreSQL and CockroachDB share one migration set, since the schema is valid in both.
- The XYZ vendor schema is invented so the adapter layer does real mapping work. If both vendors really use the brief's schema verbatim, the two adapters collapse into one configurable client.
- The `/oauth2/token` endpoint exists only behind `-dev`, so the README's curl examples work without a separate authorization server.
- The connector (Q3) is a library and is not exposed through the API.
- The Docker daemon isn't running here, so Postgres/CockroachDB contract tests will be reported as skipped unless DSNs are supplied.

**Reviewer should double-check**
- Whether the name-matching rule (exact, post-decrypt) is acceptable or whether a name blind index is wanted.
- Whether the API returning 404 for malformed IDs (instead of 400) is the trade-off you want.
- Default argon2id parameters (64 MiB / t=3 / p=4) against your target hardware.
- Commit granularity: one commit per step as requested. Red/Green cycles are not separate commits.



---

## Step Q1: DAO (issue #1, branch `1-q1-dao`)

**Produced**
- `internal/crypto`: envelope interface, local-key implementation, Vault transit stub, AES-GCM `Seal`/`Open` with AAD, HMAC blind index.
- `internal/profile`: model, `Store`, `Repository` (per-row DEK, AAD `"<id>|<column>"`, E.164 normalisation, phone search with keyset paging), `slog.LogValuer` redaction.
- `internal/credential`: `Method` type, `Validate`, argon2id `Hash`/`Verify`, `Store`.
- `internal/store/storetest`: one contract suite (6 tests). `internal/store/sqlite` and `internal/store/postgres` implement it; postgres adds `withRetry` for SQLSTATE 40001.
- Migrations (up and down) per dialect, `docker-compose.yml`, `.github/workflows/ci.yml`, README, DESIGN.md Q1, SPEC.md §1 rewritten to match what was built.
- TDD: each package's test was written and seen failing before its code. Teeth checks: removing AAD binding broke `TestSealOpen`; removing the CHECK constraint broke the contract's mismatch test.

**Assumptions**
- Scope cut to a 30-minute walkthrough at the user's request: no profile update/delete, no name filter, no opaque page tokens, no rehash detection, no versioned migration runner. Each is listed in DESIGN.md "With more time".
- The phone normaliser strips spaces, dashes, dots and parentheses, then requires `+` followed by 8–15 digits. It does not handle national formats (`(555) 123-4567` with no country code); a real one would use libphonenumber with a default region.
- `BlindIndex.Sum` is generic; normalisation lives in `profile`, so the crypto package knows nothing about phones.
- Separate store types per table (`ProfileStore`, `CredentialStore`), so each can get its own DB connection and role.
- CI skips draft PRs and runs on `ready_for_review`, matching the dgv workflow that keeps PRs in draft during review.
- `cockroachdb/cockroach:latest` is unpinned in both compose and CI; pin it for reproducibility.

**Reviewer should double-check**
- `withRetry` wraps single statements only. A multi-statement transaction must be retried as a whole: pass the whole `pgx.BeginFunc` as `fn`, not a piece of it.
- `Argon2id.Verify` trusts the parameters in the stored hash. Stored hashes are ours, but an attacker who can write `password_hash` could set a huge `m` to make verification expensive.
- `profile.open` uses a sticky-error closure to open three fields; check you find it readable.
- The Postgres `Get` maps SQLSTATE `22P02` (bad UUID text) to `ErrNotFound`; that is intentional for Q2's uniform 404.

**Pre-PR review (independent reviewer + security review)**
- Security review: no findings.
- Fixed:
  - The row-binding test would have passed without row binding. It now moves a whole sealed row under another ID and swaps columns, and was checked by breaking `aad()`.
  - argon2 `Verify` panicked on stored `t=0`/`p=0`; it now bounds all stored parameters.
  - `Search` now validates `limit` and `after`, and checks each decrypted phone against the query, so a tampered index can't leak PII.
  - `NewBlindIndex` requires a 32-byte key.
  - `Credential` logs only its ID and method.
  - `CreatedAt` is returned in UTC.
  - Retry no longer sleeps after its last attempt; DESIGN now says retries cover writes only.
- Deferred to #2: pin the CI actions and the CockroachDB image; SPEC §2 drift.
- Dropped: `Validate` treating `[]byte{}` as unset (no caller produces it).

---

## Step Q2: REST API (issue #4, branch `4-q2-api`)

**Produced**
- `internal/api`: `GET /v1/profiles/{id}`, `POST /v1/profiles/search`, `/healthz`; middleware (request ID, body cap, recover, access log, bearer auth with scopes, per-client token bucket); one error mapping with a fixed-message envelope; `Auditor` with fail-closed handlers; redacting JSON logger; in-memory dev token issuer.
- `cmd/server`: flags, keys from env (ephemeral in `-dev`), SQLite or PostgreSQL/CockroachDB, server timeouts, graceful shutdown.
- Carry-overs: CodeQL alert #1 (`crypto.Seal` capacity hint removed); `profile.Address` redacts itself in logs; SPEC §2 rewritten to match (#2 item 3).
- TDD: `api_test.go` written against a compile-only skeleton and seen failing (10 tests) before the code. Teeth checks: removing the body cap, the redaction, the scope check, the expiry check, the request-ID validation, the audit fail-closed, or logging the raw path each broke a test.
- Smoke run: seeded a SQLite file, started `cmd/server -dev`, curled get, search and an unauthenticated get, sent SIGTERM; logs held no PII.

**Assumptions**
- At the user's direction: no `/oauth2/token` endpoint (`-dev` prints a token instead); no idle-bucket eviction (buckets keyed by authenticated client ID); CI and image pinning stay in #2.
- The server refuses to start without `-dev`, because the token verifier and Vault envelope are stubs.
- An oversized body returns 400 `invalid_request` rather than 413, to keep one code for bad input.
- Unauthenticated requests are not rate-limited (the limiter runs after auth, as SPEC orders it).

**Reviewer should double-check**
- `ServeMux` sets `r.Pattern` on the request the access-log middleware holds; the route field depends on that (tested).
- `limiter.wait` cancels a reservation it won't use, so a rejected request doesn't consume a token.
- The redaction deny-list matches keys, not values: a PII value under an innocent key (`"q"`) would be logged. The LogValuers and the access log's no-body rule are the main defence.

**Pre-PR review (independent reviewer + security review)**
- Security review: no findings.
- Fixed:
  - On PostgreSQL, `GET /v1/profiles/%FF` (or `%00`) returned 500, not the uniform 404: Postgres rejects invalid UTF-8 (SQLSTATE 22021) before the UUID cast. Reproduced against compose Postgres; `Repository.Get` now returns `ErrNotFound` for any non-UUID without calling the store. The test was seen failing first.
  - The log redaction missed grouped attributes (`slog.Group("address", ...)`, `WithGroup("phone")`): slog calls `ReplaceAttr` on group members, not the group. It now checks enclosing group keys too, and lists the remaining address subfields.
  - `Cache-Control: no-store` is now set in middleware, so it covers every response as SPEC says.
  - Docs: `page_size` 0 means the default; the envelope covers 4xx/5xx; the credentials-role claim notes that migrations need a separate step; a 500's error text is logged; README explains the keys.
  - The internal-error test no longer uses a password-shaped marker.
- Verified `cmd/server -db postgres` against compose Postgres (start, get, search, SIGTERM).
- Deferred to #5: access log on panic, `-rate` validation, second-signal exit, per-request timeout, server-side audit request ID, `SlogAuditor` test, 403 `WWW-Authenticate`.

**Copilot round 1**
- Fixed: `SlogAuditor.Record` always returned nil (`Logger.Info` drops write errors), so the production auditor could not fail closed. It now writes through the handler and returns its error; a test with a failing writer was seen failing first.
- Fixed: the page-token test checked for `555`, which a UUIDv7 can contain; it now checks the token is exactly the last returned ID.

**Copilot round 2**
- Fixed: `uuid.Parse` skips the outer bytes of a 38-byte (braced) input without checking them, so `{<uuid>\x00` passed the malformed-ID check and reached PostgreSQL (500). `Get` and the search cursor now accept only the canonical lowercase form, which also gives SQLite and PostgreSQL the same answer for uppercase IDs. Tests failed first; verified on compose Postgres.

---

## Step Q3: Identity provider connector (issue #7, branch `7-q3-connector`)

**Produced**
- `internal/provider`: `IdentityProvider`, `Identity`, sentinels, `Secrets` (`StaticSecrets`, `VaultSecrets` stub), `VendorConfig` with defaults; `TokenCache` (early refresh, singleflight, `Invalidate(stale)`); `Breaker` and `Do` (per-attempt timeout, full-jitter retry on transient failures, `Retry-After` capped at `BackoffMax`); `Client`, the shared HTTP half (auth, 401 re-auth once, status mapping, https-only base URL, no redirects, 1 MiB body cap, normalisation).
- `abc` and `xyz`: encode and decode only, plus thin fakes over the shared `providertest.Fake`.
- Tests: every resilience test runs against both vendors; each `decode` is tested against literal JSON. 22 tests.
- TDD: tests written against a compile-only skeleton and seen failing (19 tests) before the code. Teeth checks: removing singleflight, the stale-token check in `Invalidate`, breaker counting, the single half-open probe, `Retry-After`, the caller-cancel check, the 401 refresh, the body cap, the https check, the transient classification and the `/auth` 404 mapping each broke a test.
- SPEC §3 as built, DESIGN Q3, README status and layout.

**Assumptions**
- At the user's direction: one shared fake with thin per-vendor fakes (not two full fakes); no fan-out or fallback across vendors (DESIGN describes it); #2 and #5 stay separate.
- `POST /identity` is a read, so it is safe to retry.
- The breaker counts lookups, not attempts, and only `ErrUnavailable` counts; not-found and bad-request answers reset it; the caller's own cancellation counts as neither.
- Matching is by phone only in the fake; how a real vendor uses `name` is unknown.
- An empty country in a vendor answer is allowed; a non-alpha-2 one is rejected as malformed.

**Reviewer should double-check**
- `TokenCache` runs the shared fetch under the first caller's context (DESIGN trade-off).
- Bad credentials cost one `/auth` call per lookup, because `ErrUnauthorized` doesn't trip the breaker.
- `Retry-After` as an HTTP date uses the wall clock, not `VendorConfig.Now`.

**Pre-PR review (independent reviewer + security review)**
- Security review: no findings.
- Fixed:
  - AC6 and AC7 had untested clauses: the breaker test now includes a vendor 400 (it must not count), and a test reads credentials under a `SecretName` different from the vendor name. Both were checked by breaking the line they guard.
  - `Retry-After` below `BackoffMax` is now tested as waited in full, not just capped.
  - Exhausted retries on attempt timeouts also matched `context.DeadlineExceeded`, so they read as the caller's timeout; the last error is now included as text only. Test failed first.
  - XYZ read a 200 body without a `data` field (`{}`, `{"error":...}`) as "no match"; it is now malformed. Test failed first.
  - The token cache checks again inside the shared fetch, so a caller arriving just after a refresh doesn't start a second `/auth`.
  - A non-alpha-2 country from a vendor is now tested as rejected; the breaker test checks that a success really closes it.
  - Doc wording in SPEC §3, DESIGN and the fake.
- Deferred to #8: waiters on a shared token fetch ignore their own context; reuse a still-valid token when an early refresh fails; a second half-open probe in a narrow race; an XYZ 404 counting as "no match".
- Dropped: `fmt` printing of the redacting types (same as `profile.Profile`, nothing prints them); fakes in the adapter packages (planned in SPEC); negative config values (operator config only).

**Copilot round 1**
- Fixed: the one re-auth on a 401 reset on every retry attempt, so `401, 503, 401` re-authenticated twice instead of returning `ErrUnauthorized`; it is now once per lookup. Test failed first.
- Fixed: the 1 MiB cap only truncated, so a valid answer padded past 1 MiB with whitespace was accepted; over-limit answers are now rejected explicitly (restoring the check I had removed as redundant). Test failed first.
- Docs: `Timeout` covers a whole attempt (token fetch, `/identity`, re-auth), not each HTTP request; that bounds an attempt's total time, so the docs now say so rather than the code changing.
