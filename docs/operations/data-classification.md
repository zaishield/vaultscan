# Data Classification Policy

Every piece of data the platform stores or processes falls into one
of four categories. The category drives the encryption, retention,
access-control, and disclosure controls applied to it.

## Categories

### P0 — Critical / Regulated
Customer-owned security findings, evidence artifacts, scan output,
cryptographic key material, audit chains, billing records,
authentication credentials.

| Control | Implementation |
| --- | --- |
| Encryption at rest | AES-256-GCM per-tenant DEK, KEK in KMS |
| Encryption in transit | TLS 1.2+ enforced; mTLS for agent connections |
| Access control | RBAC + MFA + tenant-scoped + audited |
| Audit | Every read + write logged to `audit_logs` with actor + IP |
| Retention | Per tenant + framework requirement; min 7 years for SOC2 evidence |
| Disposal | Crypto-shred via DEK retirement |
| Cross-region | Pinned via `tenants.data_region` |
| Backup | Encrypted at rest; restored only into the same residency region |

Examples:
- `findings.*`, `finding_evidence.*`, `evidence_chain_of_custody.*`
- `audit_logs.*`, `audit_archive_runs.*`
- `tenant_data_keys.*`, `agent_certificates.*`
- `users.password_hash`, `mfa_secrets.*`, `auth_tokens.*`
- `billing_invoices.*`, `subscription_seats.*`

### P1 — Sensitive
Tenant operational metadata that's not directly customer security
data but would be embarrassing / contractually sensitive if leaked.

| Control | Implementation |
| --- | --- |
| Encryption at rest | TDE / disk-level encryption (cloud provider managed) |
| Encryption in transit | TLS 1.2+ |
| Access control | RBAC + tenant-scoped + audited |
| Audit | Mutations logged; reads sampled |
| Retention | Per data-protection policy; default 2 years |

Examples:
- `tenants.*`, `partners.*`, `users.email`, `users.full_name`
- `engagements.*`, `assets.*`, `scope_targets.*`
- `agents.*` (excluding cert material)
- `integrations.config` (URLs, but signing secrets are P0)
- `login_events.*`, `token_revocations.*` (post-erasure: PII stripped)

### P2 — Internal
Operational telemetry, dashboards, scheduled-report metadata,
non-PII configuration.

| Control | Implementation |
| --- | --- |
| Encryption at rest | TDE |
| Encryption in transit | TLS 1.2+ |
| Access control | Authenticated; per-tenant where applicable |
| Audit | Aggregate only; no per-row audit |
| Retention | 12 months rolling |

Examples:
- `dashboards.*`, `reports.schedules`
- `bus_events.*` (post-process; not the payload of P0 events)
- `notification_preferences.*`
- Prometheus metrics, structured logs

### P3 — Public
Marketing material, public API documentation, branding assets,
public status / health endpoints.

| Control | Implementation |
| --- | --- |
| Encryption at rest | Not required |
| Encryption in transit | TLS for consistency |
| Access control | None |
| Audit | Aggregate access metrics only |

Examples:
- `/healthz`, `/readyz`, `/api/v1/status`, `/api/v1/branding`
- `/.well-known/jwks.json`, `/.well-known/security.txt`
- Public docs site content
- Open-source release notes

## Handling rules

| Action | P0 | P1 | P2 | P3 |
| --- | --- | --- | --- | --- |
| Store in a log line | NEVER (use a reference / ID) | Redact PII | OK | OK |
| Include in a metric label | NEVER (high-cardinality + leakage) | NEVER | Hashed only | OK |
| Send to a 3rd-party SaaS without DPA | NEVER | NEVER | Requires review | OK |
| Echo in a 500 error response | NEVER | NEVER | OK | OK |
| Cache at the edge CDN | NEVER | NEVER | Short TTL only | Long TTL OK |
| Include in a backup | Encrypted + tested restore | Encrypted | Encrypted | Optional |
| Cross-region transfer | Requires explicit residency config | Allowed within tenancy region | OK | OK |

## Engineering enforcement

- `internal/logging/redact.go` — strips known-PII fields from log lines
- `internal/observability/metrics.go` — reviewer must approve any new label whose values aren't bounded
- `audit.Record()` — required on every P0 + P1 mutation
- Code review: any new column whose name suggests P0/P1 data triggers an explicit classification + control review

## Reviews

- Per release: any new table / column added gets a classification assigned in the migration comment
- Annually: full re-walk; auditor evidence in `docs/operations/compliance-audit-pack.md`

Last reviewed: 2026-05.
