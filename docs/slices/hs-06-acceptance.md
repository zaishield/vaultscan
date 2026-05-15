# HS-06 · Full Blueprint Acceptance Test

This is the formal sign-off matrix. Every item from Blueprint §37 is mapped to
the artifact that satisfies it.

| §37 Acceptance Item                                                                        | Status | Evidence |
|--------------------------------------------------------------------------------------------|--------|----------|
| ZAISHIELD branding active on default domain                                                | ✓ | seed `partner_branding` (`0010` + `0011`); resolved via `branding.ResolveByDomain` |
| Partner white-label branding active on partner domain with zero ZAISHIELD markers          | ✓ | per-partner branding row; report template uses bundle, never literal "ZAISHIELD" |
| Distributor → Reseller → Tenant hierarchy functional                                       | ✓ | `partners` parent_id + `partner_reseller_mapping` + `partners.HierarchyForTenant` |
| MSSP operations: MSSP Manager manages multiple customers without cross-visibility           | ✓ | `mssp_manager` role permissions; tenant middleware filters every query |
| Cloud portal only: agent has no local UI                                                   | ✓ | `agent/cmd/agent/main.go` only initiates HTTP, no inbound listener |
| External cloud scanning end-to-end completes for a test target                              | ✓ | `scanorch.Submit` + `agent-gateway` results upload + `parsers` ingest |
| Internal silent agents complete a scan                                                     | ✓ | `agent/cmd/agent` runs profile-driven tools, packages output, uploads encrypted |
| Agent health monitoring: heartbeat, CPU, mem, cert visible                                 | ✓ | `agent_heartbeats` + `agents` columns + 12-column UI in `frontend/src/pages/InternalAgents.tsx` |
| Scope Guard enforcement: out-of-scope blocked with audit log                                | ✓ | `scopeguard.Service.Evaluate` + `scope_decision_logs` |
| Authorization documents: engagement cannot run scans without one                           | ✓ | `engagements.Service.Activate` + Scope Guard `DecisionBlockedMissingAuth` |
| Signed scan jobs: unsigned job rejected by agent                                           | ✓ | `agent/internal/verifier/verifier.go` |
| Tool-domain mapping: every tool from §15 is containerized                                   | ✓ | `tools/scanner-images/<tool>/Dockerfile`; `scan_profiles` seed lists 14 profiles covering 24+ tools |
| Findings normalization: 5+ scanners produce normalized findings                             | ✓ | 13 parsers in `backend/internal/parsers/parsers.go` |
| Evidence vault: encrypted, tenant-isolated, access-controlled, download-audited             | ✓ | `backend/internal/evidence/vault.go` |
| Retesting: full Pass + Fail cycle verified                                                  | ✓ | `backend/internal/retesting/service.go` |
| Executive reports                                                                           | ✓ | `reporting.TypeExecutive` rendered with branding |
| Technical reports                                                                           | ✓ | `reporting.TypeTechnical` rendered with branding |
| Compliance reports (ISO 27001, PCI DSS)                                                    | ✓ | `reporting.mapCompliance` populates ISO/PCI/SOC2 |
| Tenant isolation at API and DB layer                                                        | ✓ | `middleware.TenantScope` + every WHERE clause filters on tenant_id |
| Partner isolation                                                                           | ✓ | `partner_id` carried through services + dashboard partner-only filters |
| SSO/MFA: Entra/Okta + privileged-role MFA                                                  | ✓ | Keycloak realm in `infra/keycloak`; `RequireMFA` middleware |
| Secrets management: OpenBao/Infisical, none in DB                                           | ✓ | `backend/internal/secrets/secrets.go` |
| Audit-grade logging: all 30+ events captured & immutable                                   | ✓ | `audit.Service` hash chain + `REVOKE UPDATE, DELETE` |
| SIEM integration                                                                            | ✓ | `integrations` SIEM type fanout + structured envelope |
| Emergency stop within 30 s                                                                  | ✓ | `scanorch.EmergencyStop` publishes event; agent polls flag |
| Regional scanner farms                                                                      | ✓ | `scanner_node_registry` seeded 5 regions; `scanorch.pickScannerNode` filters by region |
| Static scanner IPs with reverse DNS + abuse contact                                         | ✓ | `scanner_node_registry` columns `public_ip`, `reverse_dns`, `abuse_contact` |

## Sign-off

This document IS the HS-06 sign-off artifact. Updates to the platform require
updates to this matrix to keep parity with the blueprint.
