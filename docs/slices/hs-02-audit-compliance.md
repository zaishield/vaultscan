# HS-02 · Audit & Compliance Hardening

| Acceptance Criterion                                                  | Implementation |
|-----------------------------------------------------------------------|----------------|
| All 30+ event types from §32.1 generate immutable `audit_logs` record | `backend/internal/audit/audit.go` defines 35 event constants; emitters in tenants/partners/engagements/scanorch/findings/evidence/agents/retesting |
| Audit logs cannot be deleted or modified via any API endpoint         | `REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC` in migration `0009_integrations_audit.up.sql`; verifier endpoint computes SHA-256 chain |
| SIEM forwarding delivers events within 10 seconds                     | `eventbus.Bus.Publish` fans out synchronously; SIEM integration delivers via direct HTTP POST |
| ISO 27001 and PCI DSS exports validated for completeness              | Compliance report type maps every finding to ISO/PCI/SOC2 controls (`reporting.mapCompliance`) |

## Hash chain

Each `audit_logs` row stores `chain_prev` (previous row's hash) and
`chain_hash = sha256(prev || serialized_row || payload)`. Tampering with any
row breaks the chain at the next read; `GET /api/v1/audit/verify` reports the
first inconsistency or 0 if intact.

## Key files

- `backend/migrations/0009_integrations_audit.up.sql`
- `backend/internal/audit/audit.go`
- `frontend/src/pages/AuditTrail.tsx`
