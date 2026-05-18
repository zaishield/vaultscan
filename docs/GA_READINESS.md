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

## ✅ Closed: foundational

### Tests actually run against a real Postgres
- The integration suite (build tag `integration`) requires
  `VAULTSCAN_TEST_DATABASE_URL` and exercises a live container.
- 257 tests passing on `postgres:16-alpine`. Unit suite green across all
  packages.
- Verify locally:
  ```bash
  cd backend && VAULTSCAN_TEST_DATABASE_URL='postgres://vaultscan:vaultscan@127.0.0.1:5432/vaultscan?sslmode=disable' \
    go test -tags=integration -count=1 ./test/integration/...
  ```

### SSRF guard test override cannot ship to production
- `SetGuardDisabledForTesting` lives behind `//go:build integration`.
  Production builds physically cannot link against it.
- Verify:
  ```bash
  # In backend/, create a tiny cmd/probe that calls the helper.
  # Without -tags=integration the build fails with "undefined".
  ```

### Refuse-to-boot on known development master keys
- `evidence.NewVault` returns `ErrDevKeyInProduction` when given any
  master KEK value in `knownDevMasterKeys`.
- Escape hatch: `VAULTSCAN_ALLOW_DEV_KEYS=true` (dev/test only).
- Three unit tests cover refusal, escape, and pass-through.

### Audit chain integrity under concurrent writes
- `pg_advisory_xact_lock` serialises read-prev + insert.
- `TestAuditChain_ConcurrentWritesStayIntact`: 8 writers × 25 events,
  chain stays intact (~450 rows/sec on test hardware).
- `TestAuditChain_HighContentionStress`: 16 × 50, same assertion.

### Audit chain verifier is restart-resumable
- Migration 0062 added `audit_chain_verification_checkpoints` (single
  row, enforced by CHECK constraint).
- `audit.VerifyIncremental` resumes from the persisted
  `(last_verified_id, last_verified_hash)` pair on the next tick.
- Cron schedule:
  - Hourly: `VerifyIncremental` (bounded, resumable)
  - Weekly: `VerifyDeep` (full re-scan, doesn't trust checkpoint —
    catches the attacker-tampered-checkpoint case)

### DLQ retry: real exponential backoff + give-up
- Migration 0063 added `last_retry_at`, `retry_count`, `give_up_at`.
- `integrations.RetryDeadLetters`: 2^retry_count-minute backoff;
  give_up_at set after maxRetries (default 8); bounded batch.
- Two integration tests verify backoff window and give-up termination.

### Adversarial fuzz coverage for the SSRF guard
- `FuzzValidateOutboundURL` (Go's native fuzzer) with 27 seeds covering
  loopback variants, IPv6 literals, cloud metadata aliases, scheme
  bypasses, credential-stuffing.
- Assertion is precise: a fuzz finding is a bug only if the URL
  resolves to a CIDR `isBlocked()` says is blocked AND the guard
  passed it.
- Recommended pre-release run:
  ```bash
  cd backend && go test -fuzz=FuzzValidateOutboundURL -fuzztime=60s \
    ./internal/integrations/
  ```

### Evidence rotation no longer silently swallows errors
- `ReWrapTenantObjects` and `RotateStaleTenantKeys` emit structured
  zerolog warns (`component=evidence`) tagged with `op`, `tenant_id`,
  `evidence_id`. Per-tenant skipped-count summary on partial failures.

### GDPR Art. 17 erasure leaves no free text on user revocation rows
- `users.Erase` re-sweeps `token_revocations.reason = NULL` AFTER
  `RevokeAllTokens` runs, so the post-erase state contains zero
  user-supplied strings on rows tied to the erased user.
- Verified by `TestUsers_EraseSweepsAllPIITables`.

### Row-Level Security applies to audit_logs
- Migration 0057 enables RLS + FORCE on `audit_logs` with the standard
  NULL-tenant escape (platform-admin tooling that doesn't set the GUC
  still sees everything).
- `TestRLS_TenantCannotReadOtherTenant_AuditLogs` verifies a
  GUC-pinned non-superuser session sees zero rows for the OTHER tenant.

---

## 🟡 Partial — meaningful but not complete

### OpenAPI request/response schemas
- **Done:** 13 highest-impact endpoints have hand-authored, type-tight
  schemas (request bodies + response shapes with enums, formats,
  required fields). See `backend/cmd/oasgen/generate.py` →
  `SCHEMA_OVERRIDES`.
- **Remaining gap:** ~210 endpoints still emit
  `{type: object, additionalProperties: true}`. Path discovery works;
  SDK codegen will produce loose types for those routes.
- **How to extend:** read the handler's `writeJSON(...)` call, model
  the response against `backend/internal/models/`, add an entry to
  `SCHEMA_OVERRIDES`, regenerate (`python3 backend/cmd/oasgen/generate.py
  docs/api/openapi.yaml`), and the contract test catches any drift.

### Load testing
- **Done:** real concurrent-writer stress on the audit chain (16 × 50,
  proves the advisory lock).
- **Remaining gap:** no end-to-end k6/vegeta-style load test against the
  full API; no soak test (multi-hour); no chaos test (kill pg / restart
  api mid-traffic). These belong in a separate `loadtest/` workstream
  that runs against staging, not in the unit/integration suite.

### Operational dependencies (Keycloak, OpenBao, S3)
- **Done:** the in-process test harness exercises every code path that
  talks to these dependencies — but it does so against stubs / pgxpool
  / filesystem storage.
- **Remaining gap:** there is no automated test that boots the real
  Keycloak / OpenBao / S3 (Ceph) sidecars and exercises the OIDC token
  exchange, secrets manager paths, or signed-URL S3 ops end-to-end.
  These should run in a staging environment as a release gate before
  any real GA promotion.

---

## ❌ Open — not addressed in this codebase yet

### Third-party penetration test
- The SSRF guard, inbound HMAC verifier, JWKS verifier, and SAML
  assertion path all benefit from an independent review. None has been
  done in-tree. Recommend booking one before customer #1.

### SOC 2 / ISO 27001 evidence collection workflow
- The audit-log + custody-event scaffolding supports it, but the
  process of producing a quarterly evidence bundle is not codified.
  See `internal/compliance/` for the pieces; integration with an
  external GRC tool is not in this repo.

### Secret-rotation rehearsal runbook
- Code supports KEK rotation (per-tenant DEK envelope), JWT-signing-key
  rotation, integration HMAC rotation, agent cert rotation. There is no
  runbook that walks an operator through a real rotation under prod
  load with a rollback path.

### Multi-region active-active database
- Single-writer Postgres today. Read replicas are documented but the
  application has no awareness of replica lag, no read-after-write
  fencing on critical reads (post-write list calls). For GA in a single
  region this is fine; for multi-region it requires real work.

### Backup / restore drill
- pg_dump-based backup is documented. Has not been exercised end-to-end
  in this repo (boot a fresh DB from a backup, verify chain integrity,
  decrypt evidence under a re-bootstrapped vault).

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
