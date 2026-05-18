# QA / Tester guide

**Primary objective:** exercise every customer-facing flow + every
operator-facing flow against a representative dataset, catch
regressions before they ship.

## Environments

| Env | When you use it | How to get one |
| --- | --- | --- |
| Local compose | Per-feature manual testing | `make bootstrap && make seed` |
| Local compose + extended fixtures | Multi-tenant / billing / compliance UI testing | `make bootstrap && SEED_EXTENDED=1 make seed` (or `cd backend && go run ./cmd/seed -extended`) |
| Local kind | Helm + cluster-level testing | `make tf-local-up CLOUD=generic ENV=dev` |
| Staging cluster | Pre-release smoke + capacity validation | provisioned by Platform team |
| QA tenant in shared prod | Live-traffic regression checks | Platform admin provisions on request |

## Test data

Two seed levels:

```bash
# Minimal demo (1 tenant, 1 engagement, 9 findings):
make seed

# Extended (3 extra tenants on 3 regions on 3 plans + 7 real users +
# 4 integrations + 3 scan jobs in 3 states + 8 compliance evidence
# rows + 7 audit log entries + notification preferences):
cd backend && go run ./cmd/seed -extended
```

The deterministic IDs in `backend/cmd/seed/extended.go` mean you can
script tests against fixed UUIDs:

```go
const (
    TenantGlobex   = "00000000-0000-0000-0000-000000000c01"  // existing
    TenantInitech  = "00000000-0000-0000-0000-000000000c10"  // EU, business plan
    TenantHooli    = "00000000-0000-0000-0000-000000000c11"  // US, enterprise + dedicated
    TenantRaviga   = "00000000-0000-0000-0000-000000000c12"  // APAC, starter plan
)
```

## How to drive each flow

### Login (dev-mode)

```bash
TOK=$(curl -s -X POST http://localhost:8080/api/v1/auth/dev-token \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@globex.example","roles":["client_admin"]}' \
  | jq -r .token)
echo $TOK   # use in subsequent curls as: -H "Authorization: Bearer $TOK"
```

In production, login goes through Keycloak / customer's IdP — the
dev-token endpoint returns 403 unless `VAULTSCAN_ENV=development`.

### Submit a scan end-to-end

```bash
# 1. Create scan
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOK" -H "X-Tenant-Id: $TENANT_GLOBEX" \
  -d '{"engagement_id":"$ENG_DEMO","profile":"external_standard_va","intensity":"standard"}'

# 2. Watch progress
curl -s http://localhost:8080/api/v1/scans -H "Authorization: Bearer $TOK" \
  -H "X-Tenant-Id: $TENANT_GLOBEX" | jq '.[] | {id,status,progress}'

# 3. Inspect findings
curl -s http://localhost:8080/api/v1/findings -H "Authorization: Bearer $TOK" \
  -H "X-Tenant-Id: $TENANT_GLOBEX" | jq '.[] | {severity,title,scanner}'
```

### Trigger an integration delivery

After step 3 above, a `finding.created` event fires. The seeded Slack
integration (id 00000000-...-301) will POST to a stub URL — check
`integration_deliveries` table for the delivery row.

### Verify RLS isolation

```bash
# Same scan submitted as tenant Globex should NOT appear under
# tenant Initech:
TOK_INITECH=$(curl -s -X POST http://localhost:8080/api/v1/auth/dev-token \
  -d '{"email":"admin@globex.example","tenant_id":"<initech>"}' | jq -r .token)
curl -s http://localhost:8080/api/v1/findings -H "Authorization: Bearer $TOK_INITECH" \
  -H "X-Tenant-Id: <initech-uuid>" | jq length
# expect: 0
```

### Compliance evidence pack

```bash
# Render a SOC2 report for the engagement:
curl -s "http://localhost:8080/api/v1/compliance/soc2/engagements/$ENG_DEMO" \
  -H "Authorization: Bearer $TOK" -H "X-Tenant-Id: $TENANT_GLOBEX" | jq
```

### Audit chain integrity

```bash
curl -s -X POST http://localhost:8080/api/v1/audit/verify-deep \
  -H "Authorization: Bearer $TOK" -H "X-Tenant-Id: $TENANT_GLOBEX" | jq
```

## Automated test suites

```bash
# Unit tests (fast, in-process):
cd backend && go test ./...

# Integration tests (real DB; requires VAULTSCAN_TEST_DATABASE_URL):
cd backend && go test -tags=integration ./test/integration/...

# Specific test:
go test -tags=integration -run TestRLS_AllTenantScopedTables \
  ./test/integration/ -v

# Coverage report:
go test ./internal/... -coverprofile=cover.out
go tool cover -html=cover.out -o cover.html
```

## Regression test matrix

| Feature | Test file | Run command |
| --- | --- | --- |
| User erasure (GDPR Art 17) | `users_erase_test.go` | `go test -tags=integration -run Users_Erase` |
| Data residency enforcement | `tenants_residency_test.go` | `go test -tags=integration -run Tenants_` |
| Inbound webhook HMAC | `integrations_inbound_test.go` | `go test -tags=integration -run Integrations_VerifyInbound` |
| KEK/DEK re-wrap | `evidence_rewrap_test.go` | `go test -tags=integration -run Evidence_ReWrap` |
| RLS cross-tenant isolation | `rls_isolation_test.go` | `go test -tags=integration -run RLS_` |
| Permission gates (403 matrix) | `permission_matrix_test.go` | `go test -tags=integration -run Permissions_` |
| HTTP handler smoke (GA endpoints) | `http_ga_endpoints_test.go` | `go test -tags=integration -run Handlers_` |
| Scanner end-to-end | `scanner_test.go` | `go test -tags=integration -run ScannerWorker_` |

## When to escalate

- Any cross-tenant data leak → security on-call IMMEDIATELY
- Any audit-chain `verify-deep` failure → engineering lead within 1 hour
- Any consistent integration delivery failure → integration owner
- Any UI-visible 500 → file P1 issue + ping engineering

## Tools

- `make integration-test` — local integration suite
- `make e2e` — Playwright (frontend)
- `make mutation` — mutation testing (weekly only)
- `make security` — gosec + govulncheck + gitleaks locally
