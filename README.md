# mandates

A take-home design exercise in Go: a DAO for user profiles and credentials, a REST API to search
profiles, and a connector to third-party identity providers. The emphasis is on design; the code
is a deliberately small proof of concept.

- [SPEC.md](SPEC.md): interfaces, data model, endpoints
- [DESIGN.md](DESIGN.md): decisions, trade-offs, what I'd do with more time
- [AI_LOG.md](AI_LOG.md): what the AI assistant produced at each step and what to double-check

## Tools and AI

**AI.** I built this with [Claude Code](https://claude.com/claude-code) running Claude Opus 5.5,
which wrote the plans, code, tests and docs under my direction and review. GitHub Copilot reviewed
each pull request. [AI_LOG.md](AI_LOG.md) records what the AI produced at each step, the
assumptions it made and what to double-check.

**Workflow.** The work ran through my own agentic development workflow (dgv-session), a Claude
Code plugin. Its key principles:

- Every non-trivial change starts from a GitHub issue with testable acceptance criteria.
- The AI writes a plan, then stops once for my approval before any code.
- Test-driven: a failing test first, and each new test is shown to fail when the code it guards breaks.
- An independent reviewer, in a fresh context, checks the whole diff before the PR opens.
- Automated PR review is answered comment by comment, with a cap on fix rounds.
- Every review finding is fixed, filed as an issue, or dropped with a reason; none is ignored.
- I review and merge every PR; the AI doesn't merge.

**Tooling.** Go 1.27.1 (pinned with [mise](https://mise.jdx.dev)); Docker Compose for PostgreSQL 17
and CockroachDB; GitHub Actions CI running `go vet` and race tests on all three databases; CodeQL
code scanning (GitHub default setup).

**Frameworks.** None beyond the standard library (`net/http`, `log/slog`, `database/sql`,
`testing`), plus six modules (SPEC.md §5 gives the reason for each): `github.com/jackc/pgx/v5` and
`modernc.org/sqlite` (database drivers), `golang.org/x/crypto` (argon2id), `golang.org/x/time`
(rate limiting), `golang.org/x/sync` (singleflight) and `github.com/google/uuid` (UUIDv7 IDs).

## Run the tests

Requires Go 1.27.1 (pinned in `mise.toml`).

```sh
go vet ./...
go test -race ./...                 # SQLite only; Postgres/CockroachDB tests skip

docker compose up -d                # PostgreSQL 17 and CockroachDB, single node
TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:5432/mandates?sslmode=disable' \
TEST_COCKROACH_DSN='postgres://root@localhost:26257/defaultdb?sslmode=disable' \
go test -race ./...                 # the same contract suite on all three databases
```

CI (`.github/workflows/ci.yml`) runs the second form on every PR.

## Status

| Part | Implemented | Stubbed / not done |
|---|---|---|
| Q1 DAO | profile repository with per-row envelope encryption and phone blind index; argon2id passwords; credential model for password, passkey and TOTP; SQLite and pgx (PostgreSQL + CockroachDB) stores; CockroachDB retry; one contract suite on all three | Vault transit envelope (`TODO` stub); profile update/delete; key rotation; versioned migration runner |
| Q2 API | profile get and search; scoped bearer auth; per-client rate limit; audit (fail closed); PII-free logs; server with timeouts and graceful shutdown | real token verifier (JWT/introspection); production keys via Vault; edge rate limiting |
| Q3 Connector | `IdentityProvider` for ABC and XYZ; token cache with early refresh and singleflight; 401 re-auth; retry with jitter and `Retry-After`; circuit breaker; credentials from `Secrets`; shared httptest fake, tests on both vendors | Vault secrets (`TODO` stub); real vendor endpoints; not exposed through the API |

## Run the server

```sh
export MANDATES_KEK=$(head -c32 /dev/urandom | base64) MANDATES_INDEX_KEY=$(head -c32 /dev/urandom | base64)
go run ./cmd/server -dev            # SQLite at ./mandates.db; prints a profiles:read token
curl -H "Authorization: Bearer $TOKEN" localhost:8080/v1/profiles/<id>
curl -H "Authorization: Bearer $TOKEN" -d '{"phone":"+15551234567"}' localhost:8080/v1/profiles/search
```

Without the two keys, `-dev` generates ephemeral ones, so data from an earlier run can't be read.
The API has no write endpoints: profiles are created through the DAO (`profile.Repository.Create`)
with the same keys.

## Layout

```
cmd/server/                API server: flags, keys, timeouts, graceful shutdown
internal/api/              handlers, middleware, auth, rate limit, audit, error mapping, redacting logger
internal/crypto/           envelope encryption, AES-GCM field sealing, HMAC blind index
internal/profile/          Profile model, Store interface, Repository (the DAO)
internal/credential/       Credential model, Store interface, argon2id hasher
internal/store/storetest/  the contract suite every store runs
internal/store/sqlite/     SQLite stores and migration
internal/store/postgres/   PostgreSQL/CockroachDB stores, migration, 40001 retry
internal/provider/         identity provider connector: client, token cache, retry, breaker, secrets
internal/provider/abc/     ABC adapter and fake
internal/provider/xyz/     XYZ adapter and fake
internal/provider/providertest/  the shared httptest vendor fake
```
