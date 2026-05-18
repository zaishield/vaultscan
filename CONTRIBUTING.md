# Contributing to VaultScan

We accept contributions through GitHub pull requests. This document
covers the engineering norms that get a PR merged quickly.

## Before you write code

1. **Open an issue first** for anything beyond a trivial fix. The
   maintainers will steer architecture before you've sunk hours.
2. **Run the bootstrap** so you have a working dev environment:
   ```bash
   make bootstrap     # docker-compose stack
   make integration-test
   ```
3. **Read the relevant Blueprint slice** under `docs/slices/`. The
   slice contains acceptance criteria a reviewer will check against.

## What we accept

| Type | Bar |
| --- | --- |
| Bug fix | Test that reproduces the bug pre-fix; passes post-fix. |
| New API endpoint | Handler test + OpenAPI entry + permission gate + integration test. |
| New cron task | Wired in `cmd/cron-runner/main.go`; leader-elected; observability metric. |
| New database table | Migration up + down; RLS policy if tenant-scoped; tested. |
| Refactor | No behaviour change; existing tests still pass; rationale in PR description. |
| Doc-only | Approved fastest — submit and move on. |

## What we reject (without exception)

- Code without tests for the new behaviour.
- Commits that disable a security gate (`--no-verify`, `// nolint:gosec`, etc.) without justification.
- New direct dependencies without a license review.
- Schema migrations that aren't reversible (down migrations must exist; can be no-ops with a comment explaining why).
- New cron tasks that aren't leader-elected.
- Handler additions that bypass `middleware.Auth` + `middleware.RequirePermission`.
- `printf`-style or string-concatenated SQL. Always use `$N` placeholders.

## Pull request shape

- **Title:** `<area>(<scope>): <summary>` (e.g. `feat(scanorch): pin scanner image digests in strict mode`)
- **Description:** what, why, and how to verify. Reference the issue
  number with `Fixes #NNN` / `Closes #NNN`.
- **Diff size:** prefer multiple small PRs over one giant PR. A 200-line PR will be reviewed in hours; a 2000-line PR can sit for a week.
- **Commits:** sign your commits (`git commit -s`). We use DCO, not CLA.

## Local development loop

```bash
# Fast loop — compose stack, no Kubernetes.
make bootstrap

# Hot-reload the API:
make watch-api

# Run the full test suite locally (~5 min):
make test               # unit
make integration-test   # requires VAULTSCAN_TEST_DATABASE_URL
make e2e               # Playwright (frontend) + Go integration

# Lint + vet + security gates the CI runs:
make lint
make security
```

## Coding norms

- **Go**: gofmt + goimports + staticcheck; project-specific overrides in `.golangci.yml`.
- **SQL**: snake_case; explicit column lists (never `SELECT *`); always parameterised.
- **Commits**: imperative mood (`Add foo`, not `Added foo` or `Adds foo`).
- **Comments**: WHY, not WHAT. The code is the WHAT.
- **No `panic()` in request paths**: return errors. `panic()` is for impossible-state assertions only.
- **No `init()` blocks** with side effects: makes testing miserable.

## Architecture-level changes

For changes that touch >3 packages, change a public API contract, or
modify the database schema in a non-additive way: open a
**design discussion** issue first. Tag with `discuss/architecture`.
A maintainer will reply within 2 business days with either approval
or a counter-proposal.

## Reporting security issues

DO NOT open a public issue for security bugs. See
[SECURITY.md](./SECURITY.md) for the coordinated-disclosure process.

## License

By contributing you agree your contribution is licensed under the
project's MIT license (see [LICENSE](./LICENSE)).
