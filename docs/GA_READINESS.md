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

### Multi-region application primitives
- `db.CurrentLSN` + `db.ReaderFresh` + `db.ReplicaLagTracker`
  implement read-after-write fencing and replica-lag observability.
- `TestReplicaLag_*` cover the primitives end-to-end against a real
  Postgres.
- Operator runbook: `docs/runbooks/multi-region-deployment.md`.

### Migration health
- `TestMigrations_FreshScratchApplyCleanly` proves every up.sql
  applies cleanly in numerical order.
- `TestMigrations_NewStyleAreIdempotent` proves the post-0057
  migrations are safe to re-apply.

### One-command release gate
- `make ga-verify FUZZTIME=60s` runs unit + integration + every
  fuzz suite + binary smoke. ~7-10 min on a developer laptop.

---

## 🟡 Partial — meaningful but not complete

### OpenAPI request/response schemas
- **Done:** 39 highest-impact endpoints have hand-authored type-tight
  schemas across auth/MFA/JWT, tenants, users, partners, engagements,
  scope, assets, scans, findings (incl. bulk), integrations, reports,
  evidence, branding, agents, dashboards, audit, identity, and the
  liveness probes.
- **Remaining gap:** ~184 of ~223 routes still emit
  `{type: object, additionalProperties: true}`. Path discovery
  works; SDK codegen will produce loose types for those routes.
- **How to extend:** read the handler's `writeJSON(...)` call,
  model the response against `backend/internal/models/`, add an
  entry to `SCHEMA_OVERRIDES` in
  `backend/cmd/oasgen/generate.py`, regenerate, the contract test
  catches drift.

### Load testing
- **Done:** real concurrent-writer stress on the audit chain
  (16 × 50 proves the advisory lock). `cmd/loadtest` binary
  drives any HTTP endpoint with p50/p90/p99 + failure-rate gates.
  Real MinIO container tests cover S3 wire-protocol behavior.
- **Remaining gap:** no end-to-end k6/vegeta-style suite at
  multi-host scale; no soak test (multi-hour); no chaos test
  (kill pg / restart api mid-traffic with Toxiproxy or similar).
  These belong in a staging-environment workstream.

### Full multi-region active-active database
- **Done:** application-level primitives — read-after-write fence,
  replica-lag tracking, replica-aware reads. Single-region deploys
  work today; primary+replica deploys work with the documented
  wire pattern.
- **Remaining gap:** the INFRASTRUCTURE layer (streaming replication
  setup, geographic routing in the CDN, cross-region failover
  promotion) is operator work, not application code. See
  `docs/runbooks/multi-region-deployment.md` for the documented
  boundary between code and infra.

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
