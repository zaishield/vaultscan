# HS-05 · Operational Guardrails & Policy

| Never-allow rule (§36.1)                          | Enforced by                                                            |
|---------------------------------------------------|------------------------------------------------------------------------|
| Out-of-scope scanning                             | `scopeguard.Service.Evaluate` (`DecisionBlockedOutOfScope`)            |
| Expired engagement scanning                        | `scopeguard.Service.Evaluate` (`DecisionBlockedExpired`)               |
| Anonymous scan creation                            | `RequirePermission("create_scan_job")` middleware                      |
| Arbitrary command execution on agents              | Agent runner only invokes allowlisted tool binaries with prebuilt args |
| Scanner UI exposure to clients                      | UI surfaces only normalized findings; raw outputs only via signed URLs |
| Shared evidence between tenants                    | `finding_evidence.tenant_id` + tenant middleware + signed URL HMAC     |
| Plain-text credentials                              | Integrations use `secret_ref`; agent certs PEM-only                    |
| Aggressive scans without approval                   | `scanorch.Submit` returns `requires_manual_approval`; route gated by `approve_aggressive_scan` |

| Always-require rule (§36.2)                       | Enforced by                                                            |
|---------------------------------------------------|------------------------------------------------------------------------|
| Tenant context                                    | `middleware.TenantScope`                                               |
| Partner context where applicable                   | Service layers carry `partner_id` from identity                         |
| Engagement context                                 | Scan / asset / finding services require `engagement_id`                |
| Scope context                                      | `scope_targets` table + Scope Guard                                    |
| Authorization document                             | `authorization_documents` count check in Scope Guard                   |
| Scan profile                                       | `scan_profiles` lookup + signed manifest                               |
| Rate limit                                         | `middleware.RateLimit` (per-identity bucket)                           |
| Audit logging                                      | `audit.Service.Record` on every state change                           |
| Evidence encryption                                | `evidence.Vault.Put` AES-256-GCM                                       |
| Agent identity verification                        | Agent gateway middleware checks fingerprint vs DB                      |
| Job signature verification                         | `agent/internal/verifier/verifier.go`                                  |

## Emergency stop drill

`POST /api/v1/scans/emergency-stop` halts every running scan within the SLA
(`VAULTSCAN_EMERGENCY_STOP_MAX_LATENCY=30s`), publishes `EmergencyStopTriggered`,
and writes an audit entry per affected job. Agents poll the bus signal each tick
and refuse new jobs while stopped.
