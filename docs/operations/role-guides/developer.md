# Developer guide

**Primary objective:** ship code that meets the engineering bar in
CONTRIBUTING.md, with the test + security gates passing locally
before you push.

## Day 1 — environment setup (90 min)

```bash
# 1. Clone
git clone <repo> vaultscan && cd vaultscan

# 2. Verify host prerequisites
docker version           # 24+
docker compose version   # v2
go version               # 1.22+
node --version           # 20+
kubectl version --client # 1.28+

# 3. Bring up the local stack
make bootstrap           # ~3 min on first run; caches afterward
make seed                # demo fixtures
SEED_EXTENDED=1 cd backend && go run ./cmd/seed -extended  # extra fixtures for QA

# 4. Sanity-check
curl http://localhost:8080/readyz       # → "ok"
open http://localhost:5173               # portal (default port)

# 5. Mint a dev JWT for ad-hoc API calls
curl -X POST http://localhost:8080/api/v1/auth/dev-token \
  -d '{"email":"admin@globex.example","roles":["client_admin"]}' \
  | jq -r .token
```

If anything in steps 1-5 fails, see `local-dev.md` troubleshooting.

## Day-to-day loop

```bash
# Hot-reload the API while you edit:
make watch-api

# Run unit tests for your package:
cd backend && go test ./internal/<pkg>/

# Run integration tests against the live compose Postgres:
make integration-test

# Run a single integration test:
cd backend && go test -tags=integration -run TestRLS_AllTenantScopedTables \
  ./test/integration/ -v

# Lint + vet + security gates the CI runs:
make vet
cd backend && golangci-lint run    # if installed locally
make security                       # gosec + govulncheck + gitleaks
```

## Repository layout (where to put things)

| You're working on | Code goes in |
| --- | --- |
| New HTTP endpoint | `backend/internal/api/handlers*.go` + `backend/internal/api/server.go` route mount |
| New service method | `backend/internal/<package>/service.go` |
| New table | `backend/migrations/00XX_<purpose>.up.sql` + matching `.down.sql` |
| New scanner tool | `tools/scanner-images/<tool>/Dockerfile` + `backend/internal/parsers/parsers.go` Parse<Tool> + `backend/internal/scanner/runner_k8s_tool_security.go` if root/caps needed |
| New cron task | `backend/cmd/cron-runner/main.go` (in the jobs slice) |
| New chart resource | `infra/helm/vaultscan/templates/<thing>.yaml` + values default |
| New Terraform module | `infra/terraform/modules/<thing>/<cloud>/` (4 cloud variants) |
| New operator runbook | `docs/operations/<name>.md` |

## Conventions

### Go

- Package naming: short, lowercase, one word (no `util`, no `common`)
- Constructor: `New(...)` returns `*Service` + a possible error
- Service methods take `ctx context.Context` first
- Service methods that mutate take `*uuid.UUID` actor — never an
  email or token
- Audit ANY mutation: `s.audit.Record(ctx, audit.Event{...})`
- Errors wrap with `fmt.Errorf("operation: %w", err)` — never lose
  context
- SQL: always parameterised `$N`; never `fmt.Sprintf` into a query

### SQL

- One migration per change set; `.up.sql` + `.down.sql` pair
- Table names: snake_case, plural (`findings`, not `finding`)
- Column names: snake_case
- Every tenant-scoped table needs RLS — see `0040_baseline_rls.up.sql`
  for the template
- CREATE INDEX needs CONCURRENTLY for any table that already has
  data in production (the migration's header comment should call
  out whether it's safe in a maintenance window or live)

### Tests

- Unit tests live next to the code they test (`*_test.go`)
- Integration tests live in `backend/test/integration/` with
  `//go:build integration` build tag
- Use `t.Parallel()` whenever possible (the harness supports it)
- New write paths NEED an integration test (per `CONTRIBUTING.md`)

## What CI runs on every PR

| Gate | Workflow | What it does |
| --- | --- | --- |
| Build | `ci.yml` | `go build ./...` against both modules |
| Unit tests | `ci.yml` | `go test ./...` |
| Integration | `ci.yml` | live Postgres → `make integration-test` |
| Lint | `ci.yml` | golangci-lint + go vet + gofmt -d |
| Frontend | `ci.yml` | typecheck + lint + Vitest unit |
| Security (SAST) | `security.yml` | gosec + Semgrep + govulncheck |
| Security (DAST) | `security.yml` | nightly Trivy on every scanner image |
| Secrets | `security.yml` | Gitleaks |
| Deps | `dependency-review.yml` | CVE + license check on PR-introduced deps |
| Helm | `helm-deploy-verify.yml` | kind cluster install of every env overlay |
| OpenAPI drift | `openapi.yml` | re-runs oasgen + diffs against docs/api/openapi.yaml |
| E2E | `e2e.yml` | Playwright against the deployed kind cluster |
| Mutation | `mutation.yml` | weekly only; targets crypto / scopeguard / findings / parsers |

If any of these fail locally, run the listed command to repro before
opening the PR.

## How to add a new endpoint (end-to-end)

```text
1. Add the route in backend/internal/api/server.go
   - Use the right middleware: Auth + TenantScope + TenantBinding +
     RequirePermission + RequireMFA (when sensitive)

2. Write the handler in backend/internal/api/handlers_<area>.go
   - Decode the body via decode(r, &req)
   - Call into the service
   - Map errors via the dedicated error-mapping helpers (residency,
     quota, unpinned-image)
   - Use writeJSON for the success response

3. Write the service method in backend/internal/<area>/service.go
   - Parameterized SQL
   - Audit every mutation
   - Publish to the event bus when other components care

4. Add an integration test in backend/test/integration/<area>_test.go

5. Add a handler-smoke test in backend/test/integration/
   http_handler_coverage_test.go (or the GA endpoints file)

6. Add a permission-gate case to permission_matrix_test.go

7. Regenerate the OpenAPI spec:
   python3 backend/cmd/oasgen/generate.py docs/api/openapi.yaml

8. Update the relevant role guide if the endpoint changes a workflow
```

## How to add a new scanner tool

```text
1. Create the Dockerfile under tools/scanner-images/<tool>/Dockerfile
   - Pin the base image to a digest
   - Install the tool from a known release
   - Set USER non-root (unless documented otherwise)
   - End with HEALTHCHECK NONE (scanner tools are batch jobs)
   - Comment any runtime elevations needed (root / hostNetwork /
     NET_RAW)

2. If the tool needs elevations, add it to backend/internal/scanner/
   runner_k8s_tool_security.go (rootContainerTools / hostNetworkTools /
   hostPIDTools / toolCapabilityAdds maps)

3. Write the parser in backend/internal/parsers/parsers.go (or one
   of discovery.go / devsec.go for the namespace-appropriate file).
   Register it in the Registry map.

4. Add the tool to backend/migrations/00XX_scanner_image_registry_*
   so the orchestrator knows about it

5. Add the tool to at least one scan profile (or document why it's
   held back) via a migration that INSERTs into scan_profiles.tools

6. Write a parser unit test using a sample output captured from a
   real run of the tool

7. Add an end-to-end fixture to backend/test/integration/
   scanner_coverage_test.go so the matrix test enforces
   tool→Dockerfile→parser→profile presence
```

## Debugging recipes

### A request returns 500

```bash
# Tail the API logs filtered to that request_id:
kubectl logs -n vaultscan -l app=vaultscan-api --tail=200 \
  | grep "request_id=<id>"

# Or against compose:
docker compose logs api | grep "request_id=<id>"
```

### A scan is stuck

See `scanner-job-stuck-pending.md`.

### Tests pass locally but fail in CI

```bash
# CI uses a clean test schema each run. Reproduce locally:
make integration-test  # drops + recreates the schema

# If still flaky, run with -count=10 to catch intermittents:
cd backend && go test -tags=integration -count=10 -run TestFlaky ./test/integration/
```

### Migrations fail on my branch

```bash
# Check that you have both .up.sql AND .down.sql
ls backend/migrations/00XX_*

# Apply ONLY your migration (after rolling back the previous):
cd backend && go run ./cmd/migrate -down 1
cd backend && go run ./cmd/migrate -up 1
```

## Onboarding checklist

After your first 2 weeks you should be able to:

- [ ] Bring up the stack from a cold start in <5 min
- [ ] Drive an end-to-end flow via curl (login → scan → finding → report)
- [ ] Identify the 3 main backend packages relevant to your work
- [ ] Run integration tests + diagnose a failing test
- [ ] Open a PR that adds an endpoint + handler + service + test
- [ ] Use ARCHITECTURE.md to explain the request flow to a non-Go peer

## Where to ask for help

- `#vaultscan-eng` Slack channel — code questions
- `#vaultscan-platform` — infra / deployment questions
- `#vaultscan-sec` — security / threat-model questions
- Architecture decisions: open a `discuss/architecture` issue
- Code review: tag the area owner (CODEOWNERS)
