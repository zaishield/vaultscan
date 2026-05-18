# Threat Model — VaultScan platform

Engineering-level threat model. Living document; revisit on each
major release and after any pentest finding.

## STRIDE per asset

### Asset: tenant data (findings, evidence, audit log)

| Threat | Mitigation | Where |
| --- | --- | --- |
| Spoofing (cross-tenant impersonation) | JWT signed; tenant-scoped middleware; RLS at DB | `internal/middleware/tenant_binding.go` + `migrations/0040` |
| Tampering (modifying past findings) | Audit chain hash-linked + TSA-anchored | `internal/audit/audit.go` |
| Repudiation (deny an action happened) | Every write writes an audit row with actor + IP + UA | `internal/audit/audit.go` |
| Information disclosure (read other tenant) | RLS + per-tenant DEK + tenant pool routing | `migrations/0040`, `internal/evidence/vault.go` |
| Denial of service | Rate limits per IP + per tenant; pool caps; quota plan | `internal/middleware/middleware.go`, `internal/billing/` |
| Elevation of privilege | RBAC + MFA on sensitive endpoints; break-glass audited | `internal/auth/` + `RequirePermission`/`RequireMFA` |

### Asset: scanner image supply chain

| Threat | Mitigation | Where |
| --- | --- | --- |
| Malicious image substitution | Cosign keyless sign + Kyverno verify policy | `.github/workflows/security.yml` |
| Tag-mutation attack | Digest pinning via `tools/scanner-images/digests.json` + strict mode | `internal/scanorch/image_digests.go` |
| Compromised dep in image | Trivy on every build; nightly re-scan | `security.yml > trivy-images` |
| Build-environment compromise | Hermetic builds; GitHub OIDC for signing | `security.yml` |

### Asset: agent gateway

| Threat | Mitigation | Where |
| --- | --- | --- |
| Rogue agent enrollment | Per-agent enrollment token (bcrypt-hashed, one-shot) | `internal/agents/service.go` |
| Cert exfiltration | mTLS; cert pinning per agent_id | `internal/agentgw/` |
| Replay of agent commands | nonce + monotonic counter per agent | `internal/agentgw/` |
| Mass disconnect / DDoS | Backoff + circuit breaker on the gateway side | runbook `agent-fleet-onboarding.md` |

### Asset: integration outbound

| Threat | Mitigation | Where |
| --- | --- | --- |
| SSRF via attacker-controlled URL | CIDR allowlist + dialer.Control re-check | `internal/integrations/ssrf_guard.go` |
| Credential leakage in logs | Sensitive-field redaction in zerolog hooks | `internal/logging/` |
| Webhook replay (inbound) | HMAC + 5-min timestamp window | `internal/integrations/inbound.go` |

### Asset: cryptographic keys

| Threat | Mitigation | Where |
| --- | --- | --- |
| Stale DEK (forever-encrypted with old key) | 90-day rotation cron + re-wrap sweep | `cmd/cron-runner/main.go` |
| KEK at rest | KMS-backed when configured; env-var fallback (dev only) | `internal/evidence/vault.go` |
| JWT signing key compromise | Rotation API + JWKS-published verify-only keys for grace | `internal/auth/jwks.go` |
| TOTP shared-secret theft | bcrypt-hashed at rest; recovery codes one-shot | `internal/auth/totp.go` |

## Trust boundaries

```
         [ external internet ]
                  │
             ◇═══════════◇ TB1: WAF + edge LB
                  │
         [ ingress-nginx ]
                  │
             ◇═══════════◇ TB2: cluster admission (RBAC, NetworkPolicy)
                  │
         [ api / agent-gw / portal pods ]
                  │
             ◇═══════════◇ TB3: middleware.Auth (JWT verify)
                  │
         [ authenticated request scope ]
                  │
             ◇═══════════◇ TB4: middleware.TenantBinding (RLS GUC)
                  │
         [ tenant-scoped DB session ]
                  │
             ◇═══════════◇ TB5: pgbouncer (pool boundary)
                  │
         [ Postgres primary / replica ]
```

A bug at any boundary is a separate severity. Defense-in-depth means
TB3 failing (JWT bypass) is mitigated by TB4 (RLS still scopes by
the GUC, which the bug couldn't set without the JWT).

## Threat actors

| Actor | Goal | Capability |
| --- | --- | --- |
| External attacker | Steal customer data, ransom, embarrass | Internet-facing surfaces, public CVEs |
| Compromised low-priv user | Lateral movement to higher tenant | Valid JWT, no MFA, no manage_* permissions |
| Malicious tenant admin | Read/write other tenant | Valid JWT + own-tenant manage_* permissions |
| Insider (eng / ops) | Bulk extraction, audit tampering | Cluster credentials, DB credentials |
| Supply chain compromise | Inject malicious dep / image | npm / go module / container registry |
| Nation-state | Persistent, sophisticated | Combination of above + zero-days |

Insider threats are bounded by audit-chain integrity (a compromised
DB user can write but can't forge the hash chain without also
compromising the TSA) and by KMS-backed KEK (a compromised DB user
can read ciphertext but not decrypt without KMS access).

## What's explicitly NOT mitigated

| Threat | Reason |
| --- | --- |
| Physical access to a cluster node | Customer is responsible for their cloud's physical security |
| Total loss of audit chain integrity (TSA + DB + KMS all compromised simultaneously) | Outside the threat model — equivalent to "attacker owns the planet" |
| Quantum cryptanalysis of current ciphers | Roadmap: post-quantum migration tied to TLS 1.3 + KMS algorithm support |
| DDoS at the cluster (vs WAF / edge) | Operator must deploy a WAF / DDoS-protect tier in front |

## Review cadence

- **Per release**: review changes against this doc; update if a new
  asset / boundary / mitigation is added.
- **Per pentest**: incorporate vendor findings into the matrix
  above.
- **Annually**: full re-walk by security lead + engineering lead.

Last reviewed: 2026-05.
