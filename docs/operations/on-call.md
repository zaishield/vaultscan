# On-Call Playbook

Owns: `#vaultscan-oncall` (PagerDuty rotation `vaultscan-primary` / `vaultscan-secondary`).

## Pre-conditions for taking the pager

- [ ] You have `kubectl` context for `vaultscan-prod-{us,eu,ae,...}` and `vaultscan-dr-*`.
- [ ] You have `psql` access to the read-replica via the bastion.
- [ ] You're in the Keycloak group `oncall_admin` (grants the
      `maintenance.override` permission so the maintenance gate
      doesn't lock you out).
- [ ] Your TOTP authenticator is enrolled (HS-01 — `mfa_status='enrolled'`).
- [ ] You have a break-glass token issued for this shift
      (`POST /api/v1/platform/break-glass` — 15-minute TTL — stored
      in 1Password under `vaultscan-oncall`).

## Severity table

| Severity | Symptom | First action |
|---|---|---|
| SEV-1 | API 5xx > 5% for > 5 min, or audit-chain break detected, or any cross-tenant data leak | Page primary + secondary; open incident channel; enable maintenance mode for writes |
| SEV-2 | A single tenant blocked from logging in; scanner farm degraded in one region | Page primary; check region health |
| SEV-3 | Single scanner image failing cosign verify; one agent's CSR loop failing | Page during business hours |
| SEV-4 | Documentation / runbook drift | File ticket |

## First five minutes

1. **Acknowledge** the page on PagerDuty within 2 minutes.
2. **Read the alert payload** before opening any other tab.
3. **Open `#vaultscan-incident-<incident-id>`** (created automatically
   by the alertmanager bot).
4. **Snapshot the metric panels** the alert points at — Grafana →
   `vaultscan/<service>` → `Share` → `Snapshot`. Drop the URL in the
   channel.
5. **Decide severity** from the table above. If unclear, choose the
   higher one — downgrading is cheaper than missing the SLA.

## Common runbooks-by-symptom

| Symptom | Runbook |
|---|---|
| API 5xx spike | [incident-response.md](incident-response.md) §API |
| Audit-chain break (`vaultscan_audit_chain_breaks_total` > 0) | [incident-response.md](incident-response.md) §AuditTamper |
| Scanner farm degraded | [incident-response.md](incident-response.md) §ScannerFarm |
| All agents heart-stopped | [incident-response.md](incident-response.md) §AgentFleet |
| Region completely down | [multi-region-failover.md](multi-region-failover.md) |
| Suspected key compromise | [kek-dek-rotation.md](kek-dek-rotation.md) §Emergency |
| Cosign trust break | [cosign-key-rotation.md](cosign-key-rotation.md) §Emergency |

## Escalation

- **Secondary on-call**: pages automatically at +15 min if primary
  hasn't ack'd.
- **Engineering manager**: page manually for SEV-1 > 30 min, any
  data-leak suspicion, or any media/legal exposure.
- **CISO**: page manually for confirmed breach, regulator-reportable
  incident, or break-glass redemption.

## Post-incident checklist

- [ ] Timeline drafted in the incident channel (events with timestamps).
- [ ] Audit chain re-verified — `curl /api/v1/audit/verify-deep`
      returns `first_bad_id: 0`.
- [ ] Maintenance mode disabled.
- [ ] Any break-glass token redeemed during incident → revoke and
      issue a postmortem note.
- [ ] PIR scheduled within 5 business days. PIR template lives at
      `docs/operations/templates/postmortem.md`.

## Audit footer

Every shift hand-off must include the on-call's signed entry in the
`#vaultscan-oncall-handoff` thread referencing the next on-call's
PagerDuty ack and the audit_logs row id (`event = ops.oncall.handoff`).
