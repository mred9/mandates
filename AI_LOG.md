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


