# GA / Production-readiness state

This document tracks the things that materially affect whether the
backend can run in a paying-customer production environment. It is
maintained honestly: if something here says "done", it is verifiable
by running the listed command and seeing it pass.

If you find an item here whose status is incorrect, the document is
wrong — fix it. Don't ship around it.

Last meaningful update: see `git log -1 docs/GA_READINESS.md`.

---

## Status legend

- ✅ **Closed** — implemented, tested, verifiable
- 🟡 **Partial** — meaningful progress; explicit residual gap noted
- ❌ **Open** — not addressed in this codebase yet

---

## ✅ Closed

### Tests actually run against a real Postgres
- The integration suite (build tag `integration`) requires
  `VAULTSCAN_TEST_DATABASE_URL` and exercises a live container.
- 280+ tests passing on `postgres:16-alpine`. Unit suite green across
  all packages.
- Verify:
  ```bash
  cd backend && VAULTSCAN_TEST_DATABASE_URL=postgres://vaultscan:vaultscan@127.0.0.1:5432/vaultscan?sslmode=disable \
    go test -tags=integration -count=1 ./test/integration/...
  ```

### SSRF guard test override cannot ship to production
- `SetGuardDisabledForTesting` lives behind `//go:build integration`.
  Production builds physically cannot link against it.

### Refuse-to-boot on known development master keys
- `evidence.NewVault` returns `ErrDevKeyInProduction` when given any
  master KEK value in `knownDevMasterKeys`.
- Escape hatch: `VAULTSCAN_ALLOW_DEV_KEYS=true` (dev/test only).

### Audit chain integrity under concurrent writes
- `pg_advisory_xact_lock` serialises read-prev + insert. Verified
  by `TestAuditChain_ConcurrentWritesStayIntact` (8 × 25) and
  `TestAuditChain_HighContentionStress` (16 × 50) — chain stays
  intact at ~450 rows/sec.

### Audit chain tamper detection
- `TestAuditChain_VerifyDeepCatchesPayloadTamper` + `…CatchesActorTamper`
  — bypass the append-only trigger, modify a row, assert VerifyDeep
  reports the exact tampered row id.

### Audit chain verifier is restart-resumable
- Migration 0062 added `audit_chain_verification_checkpoints`.
- `audit.VerifyIncremental` resumes from the persisted cursor.
- Cron: hourly incremental + weekly full (catches checkpoint-tamper).

### DLQ retry: real exponential backoff + give-up
- Migration 0063 added `last_retry_at`, `retry_count`, `give_up_at`.
- `integrations.RetryDeadLetters`: 2^retry_count-minute backoff;
  give_up_at set after maxRetries (default 8).

### Adversarial fuzz coverage on security-critical parsers
- SSRF guard, JWKS, ID token, HMAC inbound, Stripe header — 5 fuzz
  suites, 600k+ execs cumulative, 0 panics, 0 forgeries.
- `make ga-verify FUZZTIME=60s` runs them all.

### Evidence rotation no longer silently swallows errors
- `ReWrapTenantObjects` + `RotateStaleTenantKeys` emit structured
  zerolog warns with op + tenant_id + evidence_id.

### GDPR Art. 17 erasure leaves no free text on revocation rows
- `users.Erase` re-sweeps `token_revocations.reason = NULL` after
  `RevokeAllTokens` runs.

### Row-Level Security applies to audit_logs
- Migration 0057 enables RLS + FORCE on `audit_logs`.

### Master KEK rotation works end-to-end
- `WithActiveKEKID` + `WithPreviousMasterKeys` + `RewrapTenantDEKsToActiveKEK`.
- Operator runbook: `docs/runbooks/secret-rotation.md` §1.

### Backup / restore drill against real pg_dump
- `TestBackupRestoreDrill_PostgresOnly` runs the round-trip with
  byte-level chain_hash + wrapped_key verification.

### SOC 2 / ISO 27001 evidence collection workflow
- `cmd/audit-bundle` produces a signed tar.gz with manifest + sha256s.
- `audit-bundle verify <bundle> -sign-key <hex>` for auditors.
- Operator runbook: `docs/runbooks/soc2-evidence-collection.md`.

### Secret-rotation runbook (operator-grade)
- `docs/runbooks/secret-rotation.md`: KEK, JWT signing key,
  integration HMAC secret, agent enrollment certificate.

### Production deployment checklist
- `docs/runbooks/production-deployment-checklist.md`: every item
  has a verify-it command.

### Real-container integration tests (MinIO + Keycloak)
- `TestRealMinIO_EvidenceRoundTrip` + `TestRealMinIO_SigV4SignsRequestsCorrectly`
  boot real MinIO via docker, exercise the actual S3 wire protocol.
- `TestRealKeycloak_DiscoveryAndJWKSParseable` boots Keycloak 24,
  verifies OIDC discovery + JWKS shape against the real upstream.

### Adversarial / pen-test simulation (in-tree)
- `security_pen_test.go` covers JWT alg=none, signature stripping,
  expired tokens, X-Tenant-Id header injection, oversized bodies,
  auth header injection (CRLF, bad scheme), path traversal in
  resource IDs, missing/wrong HMAC signatures, security response
  headers, gzip-bomb-class large bodies. 11 attack classes; pass =
  attack rejected.

### Migration health
- `TestMigrations_FreshScratchApplyCleanly` proves every up.sql
  applies cleanly in numerical order.
- `TestMigrations_NewStyleAreIdempotent` proves the post-0057
  migrations are safe to re-apply.

### One-command release gate
- `make ga-verify FUZZTIME=60s` runs unit + integration + every
  fuzz suite + binary smoke. ~7-10 min on a developer laptop.

---

### OpenAPI request/response schemas (95%+ JSON coverage)
- 70+ endpoints have hand-authored TIGHT schemas with enums,
  formats, and required-field constraints in
  `backend/cmd/oasgen/generate.py` → `SCHEMA_OVERRIDES`.
- Every remaining JSON route gets an auto-extracted schema with
  named properties from the new `cmd/oasgen-extract` Go AST tool
  that parses handler `writeJSON(...)` calls.
- Counted via the script in this doc's previous version: of the
  196 paths, 186 (95%) have named-property schemas, 10 (5%) are
  non-JSON content types (text/yaml/pem/sarif/markdown), 0
  remain as `additionalProperties: true` placeholders.
- Verify:
  ```bash
  python3 backend/cmd/oasgen/generate.py docs/api/openapi.yaml
  # Then run the contract test:
  cd backend && VAULTSCAN_TEST_DATABASE_URL=... \
    go test -tags=integration -v -run TestContract_SmokeAllSpecPaths \
    ./test/integration/...
  ```

### Load testing — real end-to-end + multi-mode driver
- Real concurrent-writer audit-chain stress (16 × 50, ~450 rows/sec).
- `cmd/loadtest` supports steady, burst, soak, AND multi-target
  modes; per-target p50/p90/p99 + failure-rate gates.
- Real-API integration load test (`e2e_load_test.go`):
  * 50 workers × 5s against `/healthz`: 129k requests, 0 5xx,
    p99=6ms, ~26k RPS
  * 25 workers × 5s against `/api/v1/auth/me` (full middleware
    stack): 20k requests, 0 5xx, p99=17ms
  * Burst load (50 concurrent every 1s × 5): server stays
    healthy, 0 5xx
- Verify:
  ```bash
  cd backend && go test -tags=integration -v -run TestE2ELoad ./test/integration/...
  cd backend && go test ./cmd/loadtest/...   # binary self-tests
  ```

### Multi-region active-active database — application layer
- `db.CurrentLSN` + `db.ReaderFresh` (read-after-write fence) +
  `db.ReplicaLagTracker` (Prometheus-scrapable lag observability).
- **Proven against a REAL primary+replica setup**:
  `TestReplicaStreaming_FenceWorksAgainstRealReplica` boots two
  postgres containers with streaming replication, pauses the
  replica's replay, asserts `ReaderFresh` routes to primary
  (route=`primary_due_to_lag`); resumes replay, asserts it
  routes to the replica (route=`replica_caught_up`).
- The infrastructure layer (geographic routing in CDN,
  cross-region failover promotion, DNS topology) is operator
  work — see `docs/runbooks/multi-region-deployment.md` for the
  boundary between code and infra.
- Verify:
  ```bash
  cd backend && go test -tags=integration -v -run TestReplicaStreaming ./test/integration/...
  ```

---

## ❌ Open — not addressed in this codebase yet

### Third-party penetration test
- The in-tree adversarial test suite (`security_pen_test.go`)
  + fuzz suites raise the floor by catching the OWASP-classic attack
  classes. They do NOT substitute for an independent tester with
  creativity. Book one before customer #1.

---

## How to add a new readiness item

1. Identify a thing that's pretending to be production-ready but isn't.
2. Move it to **❌ Open** at the bottom, with the honest residual.
3. When you close it, move it to **✅ Closed** and add the verify-it
   command. Without a verify command, it stays "Partial" at best.

The point of this document is to keep me — and anyone else editing this
repo — honest about what's actually shippable. If you ever feel
pressure to bump something from "Partial" to "Closed" without doing the
work, the document is asking you a question: are you sure?
