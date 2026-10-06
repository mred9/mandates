# mandates

A take-home design exercise in Go: a DAO for user profiles and credentials, a REST API to search
profiles, and a connector to third-party identity providers. The emphasis is on design; the code
is a deliberately small proof of concept.

- [SPEC.md](SPEC.md): interfaces, data model, endpoints
- [DESIGN.md](DESIGN.md): decisions, trade-offs, what I'd do with more time
- [AI_LOG.md](AI_LOG.md): what the AI assistant produced at each step and what to double-check

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
