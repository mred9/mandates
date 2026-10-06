# AGENTS.md

Instructions for coding agents working in this repository. Humans start with README.md.

This is a Go proof of concept for a take-home design exercise: a DAO for user profiles and
credentials (Q1), a REST API to search and read profiles (Q2), and a connector to third-party
identity providers (Q3). The design and the reasoning matter more than the amount of code, and
that sets how changes are made here (see "How to work").

Read these before changing anything; this file does not repeat them:

- **SPEC.md**: the contract. Interfaces, data model, endpoints, error mapping, dependencies.
- **DESIGN.md**: why things are the way they are, the trade-offs accepted, what's left for later.
- **AI_LOG.md**: what each step produced, its assumptions, and what to double-check.
- **README.md**: setup, status, layout, and the tools used.

Don't add a `CLAUDE.md` or `CLAUDE.local.md`: when either exists, Claude Code reads it instead of
this file.

## Commands

Go 1.27.1 is pinned in `mise.toml` (`mise install`).

```sh
go vet ./...
go test -race ./...                 # SQLite only: the PostgreSQL and CockroachDB tests skip

docker compose up -d                # PostgreSQL 17 and CockroachDB, single node
# wait until both accept connections (a few seconds on first start), or the suite fails to open them
TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:5432/mandates?sslmode=disable' \
TEST_COCKROACH_DSN='postgres://root@localhost:26257/defaultdb?sslmode=disable' \
go test -race -count=1 ./...        # the same contract suite on all three databases

go run ./cmd/server -dev            # prints a profiles:read bearer token to stderr
```

CI (`.github/workflows/ci.yml`) runs the full form on every PR that isn't a draft.

## Rules the code depends on

Changes must keep these true. DESIGN.md and SPEC.md explain each one.

- **No PII or secrets in logs or errors.** Types that hold either (`Profile`, `Address`,
  `Credential`, `Identity`, `LookupRequest`, `Credentials`, `Token`) redact themselves as
  `slog.LogValuer`s, and `api.NewLogger` redacts by key as a backstop. Errors that reach a log or
  a client never quote a request, a vendor's response body or a secret store's error. A new type that holds PII needs a
  `LogValue`.
- **Audit before PII.** A handler records its audit event before writing personal data, and fails
  closed if the audit write fails.
- **The API never reads credentials.** It opens only the profile store, so in production it runs
  under a database role with no access to `user_credentials`.
- **PII is encrypted per row, and phone search goes through a blind index.** That rules out fuzzy
  or partial search on encrypted fields.
- **One uniform 404.** An unknown ID and a malformed one return byte-identical bodies (apart from `request_id`).
- **Vendor adapters stay thin.** A vendor package supplies only its encoder, its decoder and its
  "no match" status to `provider.New`. Retries, the token cache, the breaker and secrets belong to
  `provider.Client`.
- **Every store passes `storetest.Run`**, the shared contract suite. A new database is a new store
  plus a test that calls it.
- **Tests use real fakes**: SQLite on disk, `httptest` servers for vendors. No mocking library.
- **A new dependency needs a reason**, in a line in SPEC.md §5.

## How to work

- **An issue first.** Every non-trivial change starts from a GitHub issue with testable acceptance
  criteria. Each follow-up gets its own issue with a descriptive title and the `follow-up` label;
  never group several into a checklist.
- **A plan, then the human approves.** Before writing code, present the approach, the files, the
  tests and a size estimate, and wait for approval.
- **Test-driven.** Write a failing test for each acceptance criterion and watch it fail. Then make
  it pass, and refactor while it stays green. Show once that each new test fails when the code it
  guards is broken. Don't weaken a test to get to green.
- **Check before every commit.** There are no git hooks: run `go vet ./...` and
  `go test -race ./...` yourself.
- **Commits** reference the issue: `#<issue> <type>: <summary>` (e.g. `#21 fix: ...`).
- **One branch and one PR per issue.** An independent review comes before the PR opens. Only the
  human merges.
- **Docs move with the code.** Update SPEC.md and DESIGN.md in the same PR as the code they
  describe, and add an AI_LOG.md entry (Produced / Assumptions / Reviewer should double-check).
- **Minimal code.** This is a proof of concept to walk a reviewer through in about 30 minutes.
  Put depth in DESIGN.md, not in extra code.

On Claude Code, the `dgv-dev-workflow` plugin (the `dgv-session` skill) runs this workflow.

## Gotchas

- **Commit subjects start with `#`,** which git treats as a comment when it opens a message in an
  editor (rebase conflicts, amend), and silently drops. Use `git -c core.commentChar=';' ...`.
- **AI_LOG.md conflicts.** Parallel PRs all append to the end of it; rebase the later ones and keep
  every entry, in merge order.
- **The database tests skip quietly.** Without `TEST_POSTGRES_DSN` and `TEST_COCKROACH_DSN` they
  pass with a plain `ok` (`-v` shows the `SKIP`), so a local green run has covered SQLite only. Use
  `-count=1` with the DSNs, or a cached pass can stand in for a real run.
- **CI skips draft PRs.** It runs once a PR is marked ready.
- **`-dev` keeps data but not keys.** The default `-dsn` is `./mandates.db`, reused across runs,
  but keys are generated per run unless `MANDATES_KEK` and `MANDATES_INDEX_KEY` are set. Rows from
  an earlier run then can't be decrypted: a GET of one fails instead of returning 404.
- **The API has no write endpoints.** A fresh database returns 404 or no results until profiles are
  created through `profile.Repository.Create` with the server's keys. Without `-dev` the server
  refuses to start (the production token verifier is a TODO).

## Open work

Deferred items are open issues labelled `follow-up`:
`gh issue list --label follow-up`.
