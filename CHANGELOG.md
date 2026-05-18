# Changelog

All notable changes to VaultScan land here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — GA hardening

### Added (external + internal plane gaps — migration 0061)

- **Per-tenant SSO config** (`tenant_sso_config`): SAML / OIDC IdP
  federation as a first-class table + `ssoconfig.Service` Get/Set
  with rotation semantics (`-` clears the secret, `""` preserves).
  Endpoints: `GET/PUT /api/v1/tenants/{id}/sso`.
- **SCIM provisioning tokens** (`tenant_scim_tokens`): bcrypt-at-rest
  with `vss_`-prefixed plaintext returned once. The /scim/v2 server
  now actually mounts with bearer-token middleware so IdP connectors
  authenticate. Endpoints: 3 CRUD + the SCIM /Users endpoints.
- **Support-engineer impersonation** (`support_impersonation_sessions`):
  60-min capped, ticket-tagged, **dual-audited** (one row under the
  operator, one under the target, tied by session_id). JWT carries
  `impersonation_session_id` claim; new middleware enforces the
  session per request + increments request_count.
- **Plan-change requests** (`plan_change_requests`): customer admins
  file upgrade asks self-serve; operators decide in queue. Plan
  transitions land in `partner_plan_history`.
- **Tenant lifecycle** (`tenants.quarantine_*` columns +
  `tenant_partner_migrations`): 7-day quarantine before hard-delete
  (cron-runner purges past the window); transactional partner
  migration with history.
- **Compliance rollup** (`compliance_rollup_snapshots`): per-tenant
  per-framework coverage % + breakdown; weekly snapshots for the
  auditor "as-of" view.
- **Billing usage adjustments** (`billing_usage_adjustments`):
  finance credits / surcharges with ticket-ref. Auditable.
- **11 new event types** on the bus (TenantSSOConfigured, …,
  BillingUsageAdjusted) so integrations + analytics-indexer can
  subscribe.
- **3 new cron tasks**: tenant_purge_swept_quarantines,
  compliance_rollup_snapshot, impersonation_session_expirer.
- **DR drill** asserts every new 0061 table + the tenants.quarantine_*
  columns post-restore.

### Added (SSO federation flow — closes the last non-external pending item)

- **SAML 2.0 SP-initiated federation** (`internal/ssoflow/saml.go`)
  - `GET /api/v1/auth/sso/{tenant_slug}/saml/start` resolves the
    tenant, parses the stored `metadata_xml` (helper finds the
    HTTP-Redirect SSO URL + the IdP signing X.509), builds an
    AuthnRequest via `auth.SAMLConfig.AuthnRequestURL`, signs a
    state cookie, and 302s to the IdP.
  - `POST /api/v1/auth/sso/{tenant_slug}/saml/acs` accepts the
    SAMLResponse POST, verifies the cookie state, validates the
    assertion via `auth.SAMLConfig.ParseAndValidateResponse`, maps
    attributes into VaultscanClaims, mints a JWT, drops a
    `vaultscan_session` cookie, and 302s to `return_to`.

- **OIDC Authorization-Code + PKCE federation**
  (`internal/ssoflow/oidc.go`)
  - `GET /api/v1/auth/sso/{tenant_slug}/oidc/start` fetches +
    caches the IdP's discovery doc, generates state + nonce +
    PKCE S256, signs the state cookie, redirects to the IdP's
    `authorization_endpoint`.
  - `GET /api/v1/auth/sso/{tenant_slug}/oidc/callback` validates
    state CSRF, POSTs to `token_endpoint` for the code+PKCE
    exchange, runs the FULL id_token verifier (next bullet),
    maps claims, mints a JWT, finishes the flow.

- **Production-grade id_token verifier**
  (`internal/ssoflow/jwks_verify.go`)
  - JWKS fetched from the IdP's `jwks_uri`, cached per-URI with a
    1h soft TTL + hard refresh on `kid` cache miss (handles IdP
    key rotation without redeploys).
  - Supports RSA + EC keys (P-256/P-384/P-521); parses the JWK
    `n`/`e` and `crv`/`x`/`y` directly into `*rsa.PublicKey` /
    `*ecdsa.PublicKey`.
  - **Algorithm pinning**: closed allowlist of RS256/RS384/RS512,
    ES256/ES384/ES512, PS256/PS384/PS512. `none` refused (CVE-
    class). HS-family refused (public-key-as-HMAC-secret confusion).
  - Validates `iss` (against discovery doc's `issuer` — prevents
    IdP impersonation), `aud` (string OR array — both shapes per
    spec), `exp`, `nbf`, `iat` (with 2 min skew + 10 min replay
    window), `nonce` (against state cookie), `sub` presence.
  - Bounded JWKS body read (256 KiB) so a malicious IdP can't OOM
    the API pod.
  - Distinct error categories surface in the 401 response detail
    so operators can debug "IdP rotated" vs "wrong client_id" vs
    "clock skew" vs "spoofed iss".

- **Claim mapping** (`internal/ssoflow/service.go`): first SSO
  sign-in auto-provisions the user under the tenant's partner.
  `groups` → roles via best-effort `roles.code` match; unmatched
  groups ignored. `user.provisioned_via_sso` audit row recorded.

- **State cookie**: short-lived HS256-signed JWT carrying
  `{tid, prov, rt, cv, non}`. SameSite=Lax + Secure + HttpOnly.

- **Discovery cache** memoises OIDC discovery for 12h.

- **Self-issued JWT** uses `Verifier.IssueRSAToken` when a
  `KeyManager` is configured (production path), falls back to
  `IssueDevToken` otherwise.

- **16 unit tests** covering SAML metadata parsing (real self-
  signed cert), error paths, attribute mapping, PKCE S256 against
  the RFC 7636 example, random-string entropy, plus 11 id_token
  verification cases: RS256 happy path, alg=none refusal, HS-family
  refusal, audience mismatch, audience-as-array, issuer spoofing
  (prevents IdP impersonation), nonce mismatch (prevents replay),
  expired, iat-too-old (replay-window enforcement), kid not in
  JWKS, allowlist invariants, EC curve mapping.

### Added

- **Data residency**: per-tenant `data_region` pin (migration 0055)
  enforced on every long-lived write path (`scanorch.Submit`,
  `assets.Create`, `evidence.RecordWithDEK`). Cross-region writes
  return HTTP 451 Unavailable For Legal Reasons.
- **Inbound webhook signature framework**: HMAC-SHA256 verification
  (migration 0056), constant-time compare, 5-min replay window,
  Stripe-style header parser, encrypted-at-rest secret via
  `evidence.Vault.WrapBytes`, full audit trail in
  `integration_inbound_log`. Production default = require signatures.
- **GDPR Article 17 right-to-erasure**: `POST /api/v1/users/{id}/erase`
  pseudonymises PII across `users` + `login_events` +
  `token_revocations` in one tx; returns row-count report.
- **Bulk audit-log export**: `GET /api/v1/audit/export` streams NDJSON
  (or `?format=csv`) for SIEM / compliance pulls; row + wall-clock
  bounds prevent admin OOM (`VAULTSCAN_AUDIT_EXPORT_HARD_CAP`).
- **Customer-facing usage endpoint**: `GET /api/v1/usage` returns the
  caller's plan + live usage counts + rate-limit caps with remaining
  tokens (`middleware.Peekable` interface on the rate limiter).
- **Public status endpoint**: `GET /api/v1/status` for status-page
  integrations (version, uptime, component health, no internal
  hostnames leaked).
- **Read-replica routing**: `VAULTSCAN_DATABASE_REPLICA_URL` drives
  `db.OpenReplica` + `db.Reader`; dashboards now route reads to the
  replica. `default_transaction_read_only=on` enforced per-conn.
- **Replica-lag metric + alerts**: `vaultscan_db_replica_lag_seconds`
  scraped every 30s; `VaultScanReplicaLagging` (>60s) and
  `VaultScanReplicaUnreachable` PrometheusRule alerts.
- **KEK/DEK rotation re-wrap**: `evidence.ReWrapTenantObjects` actually
  decrypts under the old DEK and re-encrypts under the current one
  (SOC2-grade rotation, not just "fresh DEK going forward"). Hourly
  `dek_rewrap_sweep` cron walks tenants with stale-version objects
  in bounded batches.
- **Image-digest strict mode**: `scanorch.ImageDigestRegistry.SetStrict`
  refuses to dispatch unpinned scanner images in production. Errors
  with `ErrNoDigest` → API returns 503 `unpinned_scanner_image`.
- **Per-scanner-tool pod-security overrides**: kube-bench, lynis,
  openvas get the elevations they need (root, hostNetwork/PID,
  NET_RAW) via `internal/scanner/runner_k8s_tool_security.go`;
  rest stay strict.
- **NetworkPolicy egress for managed services**: chart's
  `networkPolicies.externalEgress.cidrBlocks` + `egressPorts` let
  production reach RDS / Cloud SQL / Azure DB / S3 etc. Previous
  policy only matched in-cluster pods and would have blocked every
  cloud install at boot.
- **Cron-runner**: leader-elected background worker now deployed
  everywhere (compose, helm, all four env overlays). Drives every
  Blueprint §22.4 task — SLA sweep, DEK rotation, audit verify-deep,
  partition maintenance, SIEM shipping, DEK re-wrap, …
- **Cloud-agnostic Terraform / OpenTofu**: full IaC across AWS, GCP,
  Azure, and BYO-Kubernetes; one composition shape per env
  (dev / staging / uat / prod); local kind path via
  `make tf-local-up`.
- **Tracing**: `observability.Span` helpers wired into hot paths
  (`scanorch.Submit`, `findings.Upsert`, `reporting.Generate`,
  `evidence.RecordWithDEK`, `agents.Enroll`, `cosign.VerifyImage`,
  `dashboards.Executive/Technical/Partner`, `audit.Record`,
  `integrations.deliver`).
- **Circuit breakers**: third-party HTTP (TSA + Rekor) now wrapped
  in `circuitbreaker.Breaker` instances; existing breakers on
  outbound integrations get explicit names for metric labels.
- **SCIM parser**: full vocabulary support (`eq`/`sw`/`ew`/`co`/`pr`,
  AND/OR composites, parenthesised grouping, AND-binds-tighter
  precedence) via a recursive-descent compiler.
- **Per-env Helm overlays**: `values-dev.yaml`, `values-staging.yaml`,
  `values-uat.yaml`, `values-prod.yaml` with environment-appropriate
  posture (single replica + dev-token in dev; full HA + Kyverno
  enforce + signed images in prod).
- **Compose stack hardening**: every service has a healthcheck,
  cron-runner included, `.env.example` documents every GA env var.

### Changed

- `backend/Dockerfile` now builds `/app/migrate` + `/app/seed`
  alongside `/app/api` (the helm migrations Job referenced
  `/app/migrate` but the image didn't ship one).
- `infra/helm/vaultscan/templates/portal-deployment.yaml`
  `containerPort` corrected from `80` to `8080` (production frontend
  uses nginx-unprivileged); writable volume mounts added for
  `readOnlyRootFilesystem` compatibility.
- `api` / `agent-gateway` / `portal` / `analytics-worker`
  Deployments now apply the `_security.tpl` pod + container
  security contexts that previously only scanner-worker /
  backup / pgbouncer / restore-verify used.
- `oasgen` generator picks up routes mounted under `r.Route(...)`
  blocks (was only finding top-level method calls). OpenAPI spec
  coverage 40 paths → 176 paths.
- `agent-gateway` now has an HPA (3 → 10 replicas at 60% CPU).
- `analyticsWorker.podDisruptionBudget` toggle exposed in values
  (previously hardcoded `minAvailable: 1`).
- `infra/terraform/modules/vaultscan` consumes upstream `secret_data`
  outputs directly — no more data-source chaining (cleaner
  dependency graph, no sensitive-merge noise).

### Fixed

- DR drill (`tools/scripts/dr-drill.sh`) now asserts GA tables exist
  (`tenant_data_keys`, `tenant_pool_routing`, `tenant_residency_history`,
  `integration_inbound_log`) + GA columns
  (`tenants.data_region`, `integrations.signing_*`).
- OAS generator's YAML emitter under-indented list-item nested
  values by 2 columns (e.g. `schema:` followed by `type: string` on
  the same column).
- `oasgen` chained-call regex (`\.With(...).\n\t.Post("/", ...)`) —
  multi-line chains were silently dropped from the spec.
- `pgbouncer` template passed wrong arg shape to `componentLabels`
  helper (`"root"` instead of `"Chart"+"Release"`).
- Backup CronJob `pg_dump ${PGUSER}@${PGHOST}` → uses `PGDATABASE`
  env + database name positional (was invalid syntax that would
  have failed on first scheduled run).
- Compose `docker-compose.yml` `${VAR:?err: msg}` parse error
  (inner colon in the error message confused the YAML parser).
- Helm `secret.yaml` now `fail`s the render with an actionable
  message when neither `existingSecret` nor `inline.databaseURL`
  is set (was a confusing helm error).

### Security

- **SSRF guard on every outbound integration HTTP call**
  (`internal/integrations/ssrf_guard.go`). Pre-resolves the target
  host + refuses any URL whose resolution lands in a blocked CIDR
  (cloud metadata services, RFC1918 private, loopback, link-local,
  IPv6 ULA + link-local + multicast + IPv4-mapped). A custom
  `net.Dialer.Control` callback re-checks the resolved IP at
  TCP-connect time, closing the DNS-rebinding window. Validated by
  17 test cases. Override: `VAULTSCAN_INTEGRATION_ALLOW_PRIVATE_HOSTS=true`
  (footgun, not enabled in any production overlay).
- **Per-IP rate limit on the unauthenticated auth surface**.
  Previously, rate limits only applied AFTER `middleware.Auth`
  ran, so `/api/v1/auth/dev-token`, `/api/v1/auth/mfa/verify`,
  and `/api/v1/integrations/{id}/inbound` had no brute-force
  protection. Tight defaults: 30 attempts / 5-minute window for
  auth, 120 attempts / minute for inbound webhooks.
- **`MaxBodySize` middleware now fast-rejects via Content-Length**
  before reading the body, so a malicious >32 MiB Content-Length
  header gets a 413 immediately rather than streaming the entire
  body just to discover it's too big.
- **`X-Robots-Tag: noindex, nofollow`** on every API response so
  the public surfaces (status, branding, JWKS) don't accidentally
  get indexed by search engines or LLM crawlers if a customer
  support article links them.
- **RFC 9116 security.txt** served at `/.well-known/security.txt`
  and `/security.txt` (Contact, Expires, Encryption, Policy,
  Hiring, Acknowledgements, Canonical, Preferred-Languages).
  Contact + URLs configurable via env for white-label installs.
- Production deployments default to refusing unpinned scanner
  images (`VAULTSCAN_REQUIRE_PINNED_IMAGES=true` via
  `envmode.IsProduction`).
- Inbound webhook callbacks default to requiring HMAC signatures
  (`VAULTSCAN_REQUIRE_INBOUND_SIG=true`).
- Cosign image verification via Kyverno enforced in `values-uat.yaml`
  + `values-prod.yaml`.
- Network policies expanded to cover analytics-worker + cron-runner
  + agent-gateway with explicit egress rules.
- Scanner-image build pipeline (`security.yml`) trivy-scans every
  image on every build; release tags trigger cosign keyless sign +
  digest pin in `tools/scanner-images/digests.json`.

### Operator runbooks

New ops docs in `docs/operations/`:
- `gdpr-erasure.md` — Article 17 procedure + verification queries
- `data-residency.md` — pin model, enforcement, multi-region routing
- `inbound-webhooks.md` — HMAC verification, rotation, forensics
- `replica-routing.md` — architecture, promotion, sizing
- `capacity-planning.md` — load model + measurement protocol

### Test coverage

- New integration tests (require `VAULTSCAN_TEST_DATABASE_URL`):
  `users_erase_test.go`, `tenants_residency_test.go`,
  `integrations_inbound_test.go`, `evidence_rewrap_test.go`,
  `rls_isolation_test.go` (cross-tenant RLS leak detection).
- New unit tests: per-scanner-tool security context, scim composite
  filter + precedence + parens, breaker cache concurrency,
  observability span nil-context handling, pool config per-component
  override, db replica nil-fallback, deprecation middleware.

---

## [1.0.0] — Initial Blueprint compliance

Baseline release covering Blueprint slices VS-01 through VS-12 +
HS-01 through HS-06. See `docs/slices/` for slice-by-slice acceptance.

[Unreleased]: https://github.com/zaishield/vaultscan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/zaishield/vaultscan/releases/tag/v1.0.0
