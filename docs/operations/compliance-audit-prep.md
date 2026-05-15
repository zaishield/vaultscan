# Compliance Audit Prep

Owns: platform_security_admin + auditor role.

Used when an external auditor (ISO 27001 / PCI / SOC 2 / SOX
attestor) is coming on-site. The platform stores everything the
auditor needs; this runbook is the procedure to extract it
defensibly.

## Pre-conditions

- [ ] Auditor has a temporary `auditor`-role account with TOTP MFA
      enrolled. Account expires automatically after the engagement
      (set `users.expires_at`).
- [ ] You have at least 30 days of clean
      `vaultscan_audit_chain_breaks_total == 0` history (Grafana
      → audit panel). If the chain has any break, fix that BEFORE
      the auditor arrives.

## §AuditPrep — assemble the bundle

### Step 1 — Verify the chain end-to-end

```bash
curl -fsS https://api/api/v1/audit/verify-deep | jq
# {
#   "total_rows": <N>,
#   "first_bad_id": 0,             ← MUST be 0
#   "last_good_id": <N>,
#   "detected_at": "...",
#   "detail": ""                   ← MUST be empty
# }
```

Run this in front of the auditor on Day 1. A zero `first_bad_id` is
the headline number — they want to see the platform's own integrity
report before they touch anything else.

### Step 2 — Export the timeline for the audit window

```bash
SINCE=$(date -u -Iseconds -d '-1 year')
UNTIL=$(date -u -Iseconds)
for tenant in $(psql -t -c "SELECT id FROM tenants WHERE status='active'"); do
  curl -fsS "https://api/api/v1/audit/timeline?tenant_id=$tenant&since=$SINCE&until=$UNTIL" \
    > audit-timeline-$tenant.json
done
```

This produces one JSON-Lines file per tenant. The auditor's data-
discovery tool (typically Splunk or Excel-with-jq) consumes them
directly.

### Step 3 — Compliance matrix per active engagement

For each tenant + framework the customer is asking about:

```bash
for framework in pci_dss iso27001 nist_csf soc2; do
  for eng in $(psql -t -c "SELECT id FROM engagements
                           WHERE tenant_id='$TENANT' AND status='active'"); do
    curl -fsS "https://api/api/v1/compliance/$framework/engagements/$eng.md" \
      > compliance-$framework-$eng.md
  done
done
```

The markdown contains every control + the number of unresolved
findings that map to it + severity mix. The auditor sees the
current state without needing platform access.

### Step 4 — Evidence chain-of-custody for spot-check items

The auditor will pick ~10 random evidence objects to verify
end-to-end. For each:

```bash
EV=<evidence-uuid-the-auditor-picked>
curl -fsS https://api/api/v1/evidence/$EV/chain-of-custody.md > custody-$EV.md
curl -fsS -X POST https://api/api/v1/evidence/$EV/integrity        # confirms SHA-256 stable
```

Hand the markdown directly to the auditor — it's already in their
preferred form (table of timestamped events).

### Step 5 — RLS posture demo

```bash
# Connect to the read-replica as the non-superuser "vaultscan_app"
# role. Show the auditor that with no GUC set, the auditor account
# (which is a SUPERUSER bypass) sees everything:
psql -U vaultscan_audit -c "SELECT count(*) FROM findings"
# Then switch to the app role:
psql -U vaultscan_app -c "SELECT count(*) FROM findings"
# Then set the tenant GUC:
psql -U vaultscan_app -c "BEGIN; SELECT set_config('vaultscan.tenant_id','<t>',true);
                          SELECT count(*) FROM findings; COMMIT;"
```

The third query returns only `<t>`'s findings — defense in depth
proof.

### Step 6 — Retention policy demo

```bash
curl -fsS https://api/api/v1/audit/retention-policies | jq
# [
#   {"event_prefix":"auth.","retention_days":2190,"archive_target":"s3://..."},
#   {"event_prefix":"scan.","retention_days":1095,"archive_target":"..."},
#   ...
# ]
```

Matches what migration 0030 seeded: auth-6y, scan-3y, finding-10y,
default-7y. The auditor maps these to their framework's retention
requirements.

### Step 7 — Backup + DR drill receipts

The DR drill cron writes an `audit_logs` row of type
`ops.dr.drill_completed` after each quarterly run. Pull the
last four:

```sql
SELECT occurred_at, payload->>'duration_s' AS seconds,
       payload->>'dump_key' AS dump_object
  FROM audit_logs
 WHERE event = 'ops.dr.drill_completed'
 ORDER BY occurred_at DESC LIMIT 4;
```

## §AuditFollowUp — handling findings

If the auditor raises a finding:

1. File a ticket with severity matched to the finding (P0 critical,
   P1 high, etc.).
2. Open a `audit_logs` row of type `audit.finding.raised` with the
   auditor's reference number in the payload.
3. Track resolution via the standard finding lifecycle; the auditor's
   re-test sees the closure event in `audit_logs`.

## §AuditCloseout — when they sign off

1. Ask the auditor for the signed Statement of Applicability / Letter
   of Attestation. Store in `s3://vaultscan-compliance/<framework>/<year>/`.
2. Update the README index of this runbook collection with the
   audit date in the "Last drilled" column.
3. Disable the auditor's account (`UPDATE users SET status='inactive'
   WHERE email='<auditor>@<firm>'`).
4. Rotate the auditor's break-glass token if one was issued.

## Audit footer

The audit-prep procedure itself writes events:
- `audit.prep.started`
- `audit.prep.bundle_exported` (with row counts in payload)
- `audit.prep.completed` (with auditor's name in payload)

Plus the standard `audit.finding.raised` / `audit.finding.resolved`
chain if applicable.
