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
