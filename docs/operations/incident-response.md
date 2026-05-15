# Incident Response

Owns: on-call primary; co-signed by the engineering manager when severity ≥ SEV-1.

This runbook is the **active-incident playbook** — for routine
deploys see the relevant procedure runbook instead. The on-call
[playbook](on-call.md) routes to this document by symptom.

## Pre-conditions

- [ ] You are in `#vaultscan-incident-<id>` (auto-created by alertmanager).
- [ ] You have the break-glass token from your shift in 1Password.
- [ ] You have `kubectl` + `psql` ready.

## Decision tree

1. **Is customer data at risk?** → SEV-1, freeze writes.
2. **Is the audit chain intact?** → if no, SEV-1, do NOT delete or
   modify any row, engage legal.
3. **Is the issue blast-radius bounded to one tenant?** → SEV-2,
   continue without freezing the whole platform.

## §API — 5xx spike or latency cliff

1. Check `vaultscan_http_request_duration_seconds{quantile="0.95"}`
   in Grafana. If P95 climbed inside the last 5 min, the bad
   deploy is the most likely cause — roll back the last release
   first, debug later.
2. `kubectl -n vaultscan-control rollout undo deployment/api`
3. Wait 60s; verify P95 dropped.
4. If P95 stays high after rollback → check Postgres connection
   pool saturation: `psql -c "SELECT count(*) FROM pg_stat_activity
   WHERE state = 'active'"` — saturation is `>= MaxConns - 4`.
5. If saturated, enable maintenance mode for the affected tenant
   only (see §Maintenance below) to drain load, scale the
   read-replica.

**Verification**: `vaultscan_http_requests_total{status=~"5.."}` rate
< 0.1% over 5 minutes.

## §AuditTamper — audit_chain_breaks_total > 0

**Do not** truncate or modify `audit_logs`. Even reading the row is
fine; mutating it makes forensics harder.

1. Enable maintenance mode immediately (`PUT /api/v1/platform/maintenance`
   with `enabled: true`, `reason: "audit chain integrity incident"`).
2. Snapshot the database via the DR backup procedure — even if
   nothing else moves, a snapshot pins the evidence.
3. Run `curl https://api/api/v1/audit/verify-deep` and capture the
   full JSON response (`first_bad_id`, `last_good_id`,
   `expected_hash`, `stored_hash`, `detail`). Drop in the incident
   channel.
4. Pull the row in question:
   `psql -c "SELECT * FROM audit_logs WHERE id = <first_bad_id>"`
5. Engage legal + CISO via PagerDuty.
6. **Recovery**: a tampered chain cannot be unbroken. The procedure
   is to (a) export the legal-grade chain-of-custody for everything
   up to `last_good_id` for evidence, (b) seal the gap via an
   `audit.chain.repaired` event that explicitly references
   `first_bad_id`, (c) keep the broken row in place.

**Verification**: Two-person sign-off on the recovery event. Audit
footer entries from both signers.

## §ScannerFarm — region degraded

1. Read `vaultscan_agents_by_status` + the scanner farm dashboard
   (`/scanner-farm` in the portal — Geo Nodes panel).
2. Force a sweep: `POST /api/v1/scanner/nodes/failover-sweep`.
3. Read the freshly-written `scanner_node_failovers` rows to
   confirm which nodes were degraded and why.
4. If a whole region is offline → cut DNS to a healthy region (see
   [multi-region-failover.md](multi-region-failover.md)).
5. Re-issue cosign trust for the new region's scanner pods if they
   were rebuilt: see [cosign-key-rotation.md](cosign-key-rotation.md).

**Verification**: `GET /api/v1/scanner/regions/<region>/quota`
`at_quota: false` AND at least one node `status: online` per
affected region.

## §AgentFleet — heartbeat blackout

Symptom: `vaultscan_agents_by_status{status="online"}` drops by
>50% in < 10 min while no upstream-network alert fires.

1. Pick three random affected agents from `agents` (sample, don't
   look at one customer in isolation). For each, check the last
   `agent_mtls_handshakes` decision. If they all show
   `rejected_unknown` or `rejected_revoked`, the cause is on
   our side — a CA rotation or a bad gateway deploy. Roll back the
   agent-gateway deployment.
2. If `decision = accepted` for all three but
   `agent_heartbeats.received_at` is stale, the cause is on the
   tenant network side. Wait 5 minutes; if no recovery, ticket
   the customer.
3. Check `vaultscan_emergency_stop_sla_ms` for an unexpected
   broadcast — an operator may have triggered a fleet-wide stop.

**Verification**: At least 80% of previously-online agents
re-establish within 10 minutes after the gateway rollback.

## §Maintenance — enabling / disabling

```bash
# Enable for writes only (reads stay up); reason required.
curl -X PUT https://api/api/v1/platform/maintenance \
  -H "Authorization: Bearer ${ON_CALL_JWT}" \
  -d '{"enabled":true,"reason":"DB pool saturation, draining"}'

# Disable.
curl -X PUT https://api/api/v1/platform/maintenance \
  -H "Authorization: Bearer ${ON_CALL_JWT}" \
  -d '{"enabled":false}'
```

The HS-05 maintenance gate only blocks writes; reads pass. The
on-call's break-glass token holds the `maintenance.override`
permission, so you can still mutate platform-level things while it's
on.

## Comms

- **Status page**: update statuspage.zaishield.com within 15 min of
  SEV-1 confirm.
- **Customer notification**: required for SEV-1 within 30 min via
  status page + per-tenant email (resolved via
  `partner_branding.contact_email`).
- **Regulator notification**: required within 72h for any
  GDPR/PCI/HIPAA-reportable incident. Engage legal first.

## Audit footer

The incident channel transcript + the PIR doc must reference an
`audit_logs` row of type `ops.incident.opened` and `ops.incident.closed`,
plus row ids for any maintenance toggle and any break-glass redemption.
