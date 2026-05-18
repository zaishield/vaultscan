# Support engineer guide

**Primary objective:** debug customer-reported issues without
escalating to engineering, while staying inside the impersonation +
audit-trail discipline.

## Access you have

| Capability | How |
| --- | --- |
| Read any tenant's audit log | `view_audit_logs` permission + tenant scope override |
| Read tenant configs + integrations | `view_settings` permission |
| Read evidence metadata (not contents) | `view_evidence_metadata` permission |
| Trigger a re-test | NO — you ask the customer |
| Reset MFA | YES with `manage_mfa` + customer confirmation in writing |
| Impersonate the customer's user | Operator-controlled — see Impersonation below |
| Change customer plan | NO — escalate to Finance |
| Delete data | NO — escalate to Engineering |

## Day-to-day workflow

### 1. Get the request

Customer files via support portal / email / Slack. First action:

1. Acknowledge within 15 min during business hours
2. Open a ticket with: tenant_id, customer email, brief description
3. Search the audit log for the timeframe + actor

### 2. Pull the audit trail

```bash
ADMIN_JWT=$(...)   # from your IdP-federated session
TENANT_ID=<from ticket>

# Last 50 events for this tenant:
curl -s "https://api.<env>/api/v1/audit/export?from=2026-05-18T00:00:00Z" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-Id: $TENANT_ID" \
  | head -50 | jq

# Filter by event type (e.g. "user.login"):
curl -s "https://api.<env>/api/v1/audit/export?event=user.login&from=..." \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-Id: $TENANT_ID"
```

### 3. Inspect the user's recent activity

```bash
# Login events for one user:
psql "$VAULTSCAN_DATABASE_URL" -c "
  SELECT occurred_at, event, payload->>'ip', payload->>'ua'
    FROM audit_logs
   WHERE actor_id = '<user-id>'
   ORDER BY occurred_at DESC LIMIT 50;
"
```

### 4. Common issues + fixes

| Symptom | Probable cause | Fix |
| --- | --- | --- |
| "Can't log in" | MFA out of sync / IdP cert rotated | See MFA reset below |
| "Don't see findings" | Tenant pinned to different region | Check `tenants.data_region` |
| "Scan stuck queued" | Quota hit / agent offline | See `scanner-job-stuck-pending.md` |
| "Integration not firing" | Event filter too strict / DLQ depth high | Check `integration_deliveries` + DLQ |
| "Report wrong" | Cached or wrong framework | Re-render report; verify framework code matches |
| "Can't upload evidence" | WORM lock active / quota | Check `evidence_chain_of_custody` |
| "Webhook signature failed" | Customer's clock skew >5 min | Confirm timestamp window in `inbound-webhooks.md` |

### 5. MFA reset

ONLY after written confirmation from a known-good customer admin.

```bash
# Disable MFA for one user (they re-enrol next login):
curl -X DELETE "https://api.<env>/api/v1/auth/mfa" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d '{"user_id":"<id>"}'
```

This emits a `user.mfa_reset` audit event. Document the support
ticket ID in the audit row's `payload.note` field.

### 6. Impersonation (debug-only, audited)

**This is a privileged action. Every impersonation is logged.**

Currently NOT implemented end-to-end — see Limitations below. Until
it ships, ask the customer to screen-share OR send you the JSON
response of the failing API call.

## Limitations (be honest with customers)

- **No native impersonation yet.** When you need to see what the
  customer sees, ask them to screen-share or capture HAR.
- **No bulk-export-evidence.** Evidence is per-blob via the API; no
  "export everything for tenant X" tool.
- **No "rewind dashboards"** — you see live data; historical
  snapshots only as far back as `finding_history` partition retains.
- **No customer-facing chat** — support is reactive (ticket / email)
  not in-product.

## When to escalate

| Escalate to | When |
| --- | --- |
| On-call SRE | 5xx > 1% sustained / DB pool warning / agent fleet >50% offline |
| Engineering | reproducible bug / data inconsistency / audit chain break |
| Finance | plan dispute / billing question |
| Security | suspected breach / credential leak / unusual auth pattern |
| CSM | customer churn risk / contractual issue |
| Compliance | DSAR (GDPR data subject access request) / audit fail |

## Tools you have

- `psql` against the read-replica (NEVER the primary for ad-hoc
  reads — replica is sized for this)
- `kubectl logs` against the API namespace (read-only role)
- The support-eng dashboard in Grafana (view-only on every panel)
- The audit-export endpoint (NDJSON / CSV)

## Audit hygiene

- EVERY action you take generates an audit row. Make them meaningful:
  use `?support_ticket=ZD-1234` in URLs so the audit payload carries
  the ticket reference.
- NEVER share a customer JWT in chat / tickets / email
- NEVER paste customer data into screenshots without redaction
- ALWAYS get written confirmation before MFA reset, password reset
  (when it ships), or any destructive action

## Daily ritual

- Morning: scan the open-ticket queue, ack any P1
- 11am: check `integration_dead_letter_depth` metric — investigate
  spikes
- 3pm: review the previous day's audit-export for unusual patterns
- 5pm: hand-off to the next-shift support engineer

## Knowledge base

The 29 runbooks under `docs/operations/` cover every incident class
the system knows about. Memorise the top 10:

1. `incident-response.md` (parent)
2. `on-call.md`
3. `customer-escalation.md`
4. `replica-routing.md`
5. `kek-dek-rotation.md`
6. `agent-fleet-onboarding.md`
7. `inbound-webhooks.md`
8. `gdpr-erasure.md`
9. `data-residency.md`
10. `scanner-job-stuck-pending.md`
