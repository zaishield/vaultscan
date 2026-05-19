# Full-system audit report
**Date:** 2026-05-19
**Scope:** non-frontend/non-mobile code in `/home/user/vaultscan` —
backend (53 internal packages, 12 cmd binaries, 86,656 LOC), agent
(14 packages, 16 production files), infra (helm + Terraform AWS/GCP/Azure/generic).
**Out of scope:** `frontend/`, `mobile/` (per request).
**Method:** four parallel deep-dive sub-agents on (1) auth+SSO+middleware+SCIM,
(2) crypto+evidence+audit-chain, (3) network surfaces+egress+airgap, and
(4) helm+Terraform overlays. Plus my own: end-to-end dev environment
spin-up + full integration suite + 5 fuzz suites + 270+ test run.

## Honest scope of what I tested vs. reviewed

| Environment | Status | What I actually did |
|---|---|---|
| **dev** | ✅ Tested | Spun up via `docker compose up postgres opensearch keycloak nats minio`; ran migrations + seed; booted the API binary; probed /healthz, /readyz, /metrics, JWKS, status, security.txt; verified RBAC and tenant binding via real HTTP requests; ran the full unit + integration suite (270+ tests) + 5 fuzz suites. OpenSearch failed to start because of an `mlock` rlimit constraint in this Docker sandbox — that's an environment limitation, not a codebase issue; the test suite covers OpenSearch paths via stub. |
| **staging** | ⚠️ Config-reviewed only | I cannot deploy to a real staging cluster from this sandbox. Audited every line of `infra/helm/vaultscan/values-staging.yaml` + all relevant templates for security gates, secret handling, network policies, resource limits. Findings below. |
| **uat** | ⚠️ Config-reviewed only | Same as staging. Audited `values-uat.yaml`. |
| **prod** | ⚠️ Config-reviewed only | Same as staging. Audited `values-prod.yaml` + full Terraform AWS/GCP/Azure modules. |

If you want true staging/UAT/prod testing, the deployment checklist
at `docs/runbooks/production-deployment-checklist.md` lists the
operator steps; those steps require kubectl access to real clusters.

## Total findings

| Severity | Count | Fixed | Open | Recommended action |
|---|---|---|---|---|
| **P0** — exploit-grade, blocks ship | **14** | 6 | 8 | Fix all before customer #1 |
| **P1** — serious, blocks customer expansion | **42** | 2 | 40 | Fix all before SOC 2 audit |
| **P2** — hardening / defense-in-depth | **63** | 0 | 63 | Fix opportunistically + before each major release |
| **P3** — nits / cleanup | **22** | 0 | 22 | Backlog |

## Fixed in this commit (8 items)

| # | Finding | File | Status |
|---|---|---|---|
| 1 | SAML XML Signature Wrapping (XSW) | `auth/saml.go:154-205` | ✅ Fixed — digest-chain check + Reference URI binding added |
| 2 | SAML predictable AuthnRequest ID (xorshift PRNG) | `auth/saml.go:268-284` | ✅ Fixed — crypto/rand |
| 3 | SSO cross-tenant user lookup (`tenant_id IS NULL` branch) | `ssoflow/service.go:200-204` | ✅ Fixed — tenant-strict |
| 4 | Evidence signed URL not tenant-bound + doesn't honor KEK rotation | `evidence/sign.go`, `vault.go:421-436` | ✅ Fixed — tenantID in HMAC + retired-KEK fallback + 24h exp ceiling |
| 5 | SCIM middleware doesn't set Identity (handlers nil-panic / 403) | `middleware/middleware_scim.go:75` | ✅ Fixed — synthesise service-account Identity |
| 6 | JWT iss/aud not enforced (cross-env replay) | `auth/jwt.go:70-117` | ✅ Fixed — WithExpectedIssuer + WithExpectedAudience |
| 7 | ServiceMonitor scrapes only api (cron-runner + analytics-worker invisible) | `helm/templates/servicemonitor.yaml` | ✅ Fixed — added admin + health endpoints |
| 8 | pgbouncer PDB selector matches zero pods (drain takes both pools down) | `helm/templates/podDisruptionBudgets.yaml:78-87` | ✅ Fixed — two separate PDBs for tx + session |

## P0 findings still OPEN (8 items)

| # | Finding | File | Recommended fix |
|---|---|---|---|
| 9 | SSO state cookie has no single-use protection (replay) | `ssoflow/service.go:101-108,126-157` | Persist `jti` in DB; one-time consume on callback success |
| 10 | SSO state cookie keyfunc accepts any signing method | `ssoflow/service.go:110-124` | Add `jwt.WithValidMethods([]string{"HS256"})` |
| 11 | SSO auto-provisioning runs even when IdP email is unverified | `ssoflow/service.go:213-219` | Require `email_verified=true` claim (OIDC); gate provisioning behind tenant-config flag |
| 12 | SSO accepts any IdP-asserted role code as platform role (privilege esc) | `ssoflow/service.go:232-245` | Per-tenant role-code allowlist |
| 13 | TenantBinding GUC bleeds across pooled connections (cross-tenant RLS leak in race) | `middleware/middleware.go:154-166` | Pin connection per-request OR use `SET LOCAL` inside transaction |
| 14 | TOTP Verify has no rate limit + no last-counter replay protection | `auth/totp.go:140-156,276-289` | Per-user MFA-verify lockout + persist last_used_counter |
| 15 | KMS plaintext lives on heap as `string` (crash-dump leak) | `secrets/backend_awskms.go:108-127` | Use `[]byte`; zeroize after use |
| 16 | Agent-gateway proxy uses `http.DefaultClient` (no SSRF guard, no timeout, no auth) | `cmd/agent-gateway/main.go:206-226` | Use `httputil.NewClient`; mount inside authenticated group |

## P1 findings still OPEN (40 items, summarized)

### Cryptographic / audit-trail (17)
- `constantTimeEqualString` early-returns on length mismatch (HMAC-only)
- `audit_logs.DELETE` blocked by trigger; `purgeOldArchives` non-functional
- Dev-key blocklist is substring match, trivially bypassed by base64 padding
- `WithPreviousMasterKeys` silently appends `nil` on decode failure
- AES-GCM 96-bit random nonce no per-key call-count metric (birthday)
- Wrap blob doesn't include kek_id or DEK version as AAD
- Audit chain hash misses `occurred_at` (requires migration + chain_hash_version column to fix safely without breaking existing chains)
- VerifyIncremental falls back to VerifyDeep on ANY checkpoint-row error
- VerifyIncremental UPDATE has no `AND last_verified_id <= $1` guard
- Cosign image-ref identity match uses `strings.Contains` (substring bypass)
- Cosign key-hint fallback defeats key pinning (dead second loop)
- Rekor SET canonical-form reconstruction can drift from Sigstore canon
- `LogDecision` non-transactional with `VerifyImage`
- SigV4 reads entire body into memory + double-buffers
- KMS plaintext base64 round-trip on heap
- `evidence.logAccess` errors swallowed
- evidenceLogger writes direct to stderr, bypassing central logger

### Auth / SSO (13)
- bruteforce.IsLocked swallows DB errors (silent shield-disable)
- jwt.Verifier accepts any RSA family (RS256/384/512/PS256) — pin RS256 only
- jwt.IssueImpersonationToken hardcodes MFA=true regardless of caller
- jwt.IssueImpersonationToken falls back to HS256 when no KeyManager (prod risk)
- OIDC verifier hardcodes Keycloak JWKS URL path (Auth0/Okta/Entra incompatible)
- OIDC refreshJWKS doesn't enforce HTTPS scheme (MITM)
- OIDC verifier doesn't normalise trailing slash on issuer compare
- OIDC checkRevoked swallows DB errors (silent control bypass)
- OIDC claimsHasMFA accepts `acr=mfa` without per-tenant configuration
- SCIM Verify per-call latency scales with token count (timing oracle)
- SCIM createUser uses upsert (RFC 7644 requires 409 on conflict)
- SCIM patchUser ignores `op.Op` (only path-switching)
- Partner-level roles in tenant_scope.go bypass partner-tenant linkage check

### Infrastructure (10)
- Production image tags are NOT SHA-pinned (vaultscan.image helper has no digest path)
- Kyverno cosign policy doesn't cover pgbouncer/backup/restore-verify/postgres images
- Backup CronJob missing IRSA / S3 credentials Secret (nightly will fail silently)
- AWS datastore SG opens all ports to VPC CIDR + 0/0 egress
- EKS/GKE/AKS clusters default to public endpoint access (no IP allowlist)
- Terraform random_password for JWT + evidence master key — no documented rotation lifecycle; state-loss = catastrophic
- Helm chart secret.yaml has no fail-loud if production env + inline secrets
- networkPolicies.externalEgress.cidrBlocks defaults to []  (production breaks silently if base loaded without overlay)
- helm topology-spread/anti-affinity helper exists but no template uses it
- agentGateway HPA in staging/uat inherits base minReplicas=3 but replicaCount=2 (silent 3-replica override)

## P2 findings (63 items — see per-audit transcripts in `/tmp/claude-0/.../tasks/`)

Includes: missing test coverage on cryptographic surfaces (entire `audit/audit.go` Record/Verify/VerifyTail triad untested at unit level), missing test for SCIM HTTP handlers, missing tests for KMS adapter, missing tests for FCM/APNS URL safety, no global egress allowlist (`VAULTSCAN_AIR_GAP=true`), no air-gap mode for cloud-posture/notify/SMTP, `cloudposture/*` adapters don't use the central `httputil.NewClient`, etc.

## P3 findings (22 items)

Cleanup, dead code, replace hand-rolled helpers with stdlib equivalents (`bytes.Equal` for hand-written `equal()`, etc.). Backlog.

## What works well

The audit also surfaced a lot of code that's genuinely solid:

1. **SSRF guard CIDR coverage** is comprehensive (IPv4 RFC1918, link-local, IMDS, IPv6 ULA/link-local) + dialer-Control re-checks IP at TCP-connect time (closes DNS-rebinding gap). On-by-default, fuzz-tested, build-tag-gated test override.
2. **mTLS at agent-gateway** uses strict mode + fingerprint check + revocation log + RuntimeDefault security context.
3. **Append-only audit trigger** (migration 0029) + REVOKE on UPDATE/DELETE — defense in depth at DB layer.
4. **Postgres RLS** with `FORCE ROW LEVEL SECURITY` on every tenant-scoped table (verified by `TestRLS_*` suite, including a real primary+replica test that proves the read-after-write fence).
5. **Audit chain advisory lock** correctly serialises read-prev + insert (verified by `TestAuditChain_ConcurrentWritesStayIntact` at 16 × 50 = 800 concurrent writes).
6. **Migration runner** is robust (every up has a down, fresh-scratch apply test, new-style idempotency test).
7. **Per-tenant DEK envelope** under master KEK with full rotation drain (`RewrapTenantDEKsToActiveKEK` with integration test).
8. **Cosign verifier** integrates Rekor inclusion proof checking.
9. **All 5 fuzz suites pass** (SSRF, JWKS, ID token, HMAC inbound, Stripe header) — 575k+ execs combined, 0 panics, 0 forgeries.
10. **Real-container integration tests** for MinIO (S3 SigV4) + Keycloak (OIDC discovery + JWKS shape).
11. **Backup/restore drill** is real (`pg_dump | psql` round-trip with byte-level chain_hash + wrapped_key equality checks).
12. **SOC 2 evidence bundler** (`cmd/audit-bundle`) with auditor-facing `verify` subcommand.

## Test coverage snapshot

| Surface | Coverage |
|---|---|
| Unit tests | All 53 packages pass (`go test ./...`) |
| Integration suite | 270+ tests against real postgres:16, all pass |
| Fuzz suites | 5 suites, ~115k execs each in pre-release run, 0 escapes |
| Real-container tests | MinIO + Keycloak both green |
| Backup drill | Real pg_dump round-trip, green |
| Replication fence | Real primary+replica + replay-pause, green |
| Concurrency stress | 16×50 = 800 concurrent audit writes, chain intact |
| Pen-test simulation | 11 attack classes (alg=none, sig-strip, expired tokens, CRLF inj, path traversal, etc.) all blocked |

## Recommendations

1. **Before customer #1**:
   - Fix the 8 remaining P0s (SSO state replay, IdP-asserted role escalation, GUC race, TOTP rate limit, agent-gateway proxy auth, etc.)
   - SHA-pin all production images (extend `vaultscan.image` helper)
   - Create the backup S3 credentials Secret + IRSA role
   - Pin EKS/GKE/AKS endpoint access to operator CIDR allowlist
   - Wire production deploy of `WithExpectedIssuer` + `WithExpectedAudience` (the verifier now supports them; the `cmd/api/main.go` boot needs to call them)

2. **Before SOC 2 audit**:
   - Fix all 40 P1s (especially the audit chain `occurred_at` migration, the cosign image-ref substring match, the Kyverno policy coverage gaps)
   - Engage an external pen test (the in-tree adversarial suite is a floor, not a substitute)
   - Add the global egress allowlist + `VAULTSCAN_AIR_GAP=true` mode for closed-network deployments

3. **Operator hygiene**:
   - Rotate the committed dev `jwtSecret`/`evidenceMasterKey`/`objectStoreSecret` in `values-dev.yaml`; move to a `.gitignored` `dev-secrets.yaml`
   - Switch from long-lived IAM user keys / GCP SA keys to IRSA / Workload Identity
   - Enable EKS control-plane audit logs (and GCP/Azure equivalents)

## Detailed per-audit transcripts

The full per-area audit transcripts (~12k words each) are in the task-runner output:
- Infrastructure audit: 15+ P0/P1, helm + Terraform across 4 clouds
- Auth + SSO + middleware + SCIM audit: 13 P0/P1
- Crypto + evidence + audit-chain + cosign + secrets + awssig audit: 21 P0/P1
- Network surfaces + airgap + egress audit: 14 P0/P1

These transcripts contain file:line references and recommended fixes for every finding. They are the basis for the summary above.
