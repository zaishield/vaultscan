# Finance / Billing Ops guide

**Primary objective:** keep customer plans + usage in sync with
contract terms; surface anomalies to CSM / sales before they become
collections issues.

## What's automated (the platform does this)

| Capability | Endpoint / Mechanism |
| --- | --- |
| Per-tenant usage rollup | `billing.daily_rollup` cron task (24h interval) |
| Quota enforcement | Per-plan caps in `migrations/0023_billing_plans.up.sql`; returns 402 on exhaustion |
| Rate-limit per plan | `internal/middleware/middleware.go` + per-tenant multiplier |
| Quota-block audit trail | `audit_logs` rows with event=`quota.exhausted` |
| Usage visibility | `GET /api/v1/partners/{partner_id}/billing/usage` |
| Plan visibility | `GET /api/v1/partners/{partner_id}/billing/plan` |
| Quota-warning notification | `notify.Service` fires at >80% utilisation |

## What's manual (you do this)

### Plan change (upgrade / downgrade)

```bash
ADMIN_JWT=$(...)
PARTNER_ID=<from CRM>

# 1. Inspect current plan + usage:
curl -s "$API/api/v1/partners/$PARTNER_ID/billing/plan" \
  -H "Authorization: Bearer $ADMIN_JWT" | jq

curl -s "$API/api/v1/partners/$PARTNER_ID/billing/usage" \
  -H "Authorization: Bearer $ADMIN_JWT" | jq

# 2. Apply the change (requires `create_tenant` permission):
curl -X PUT "$API/api/v1/partners/$PARTNER_ID/billing/plan" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"plan":"enterprise","effective_at":"2026-06-01T00:00:00Z"}'

# 3. The change emits a `partner.plan_changed` audit row. Verify:
curl -s "$API/api/v1/audit/export?event=partner.plan_changed&from=2026-05-01" \
  -H "Authorization: Bearer $ADMIN_JWT" | head -10 | jq
```

Plans: `trial | starter | team | business | enterprise | enterprise_plus`.
See `billing-plans-quotas.md` for the full per-plan capability + quota matrix.

### Quota override (custom contract)

Some enterprise contracts allow temporary or contractual overrides
above the base plan's caps. Encode them in `custom_overrides`:

```bash
curl -X PUT "$API/api/v1/partners/$PARTNER_ID/billing/plan" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "plan":"enterprise",
    "custom_overrides":{
      "concurrent_scans": 150,
      "monthly_scans":   500000,
      "users":           10000,
      "evidence_retention_days": 2555
    }
  }'
```

### Quota-block investigation

When a customer is hitting 429 / 402, check:

```bash
curl -s "$API/api/v1/partners/$PARTNER_ID/billing/blocks?since=24h" \
  -H "Authorization: Bearer $ADMIN_JWT" | jq
```

Returns the rolling 24h list of quota-exhausted requests with the
endpoint + cap that fired. Decide:
- legitimate use → recommend plan upgrade to CSM
- runaway client → email customer admin + suggest rate-limiting
  their own integration

### Manual usage adjustment / credit

NOT implemented as a self-service endpoint. Open an engineering
ticket if you need to credit usage hours back to a customer (e.g.
they were affected by a platform incident). The fix happens via SQL:

```sql
-- Engineer-only; run in transaction, document the ticket ID:
UPDATE billing_usage
   SET scans_run = scans_run - 100,
       note      = note || ' [credit: ticket ZD-1234]'
 WHERE partner_id = $1
   AND month = date_trunc('month', now());
```

Engineering then audits the adjustment via `audit_logs` event
`billing.manual_adjustment`.

### Dunning workflow

NOT yet built into the platform. Today:

1. Stripe webhooks deliver `invoice.payment_failed` to your billing
   system (NOT the platform).
2. Your billing system tags the partner in CRM.
3. After N days, you ask the platform admin to set the partner status
   to `suspended`:
   ```bash
   curl -X POST "$API/api/v1/partners/$PARTNER_ID/suspend" \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"reason":"non-payment"}'
   ```
4. Suspended partners + their tenants get 402 on every endpoint
   except read-only billing + auth.

Productionizing this loop is on the roadmap; today it's an
operational hand-off.

## Reporting + month-end

```bash
# Aggregate per-partner monthly usage CSV:
curl -s "$API/api/v1/platform/billing/monthly?month=2026-05" \
  -H "Authorization: Bearer $ADMIN_JWT" -o usage-2026-05.csv

# Then upload to your accounting system (Stripe / Recurly / Chargebee /
# QuickBooks). The platform doesn't ship a native invoicing module.
```

## What you watch for

| Signal | What it means | Action |
| --- | --- | --- |
| Sustained >80% plan utilisation | Customer likely needs upgrade | CSM outreach |
| Usage drops to ~0 for a paid customer | Churn risk / integration broken | CSM outreach + technical investigation |
| Quota-block spikes | Misconfigured client OR upgrade opportunity | Reach out within 24h |
| Trial → no upgrade by D29 | Sales touch point | CSM owns |
| Partner suspended >30 days | Cancel + offboard | CSM + Compliance for retention obligations |

## Limitations (be honest)

- **No native invoicing pipeline** — the platform tracks usage; you
  invoice via a separate Stripe / accounting tool.
- **No dunning automation** — manual workflow per above.
- **No customer-facing plan upgrade page** — upgrades require an
  operator-side PUT (or sales conversation).
- **No usage forecasting** — what's in `billing_usage` is current
  + last-N months; trending UI not shipped.

## When to escalate

| To | When |
| --- | --- |
| CSM | Plan-upgrade conversation needed |
| Engineering | Quota cap appears wrong / billing rollup looks off |
| Sales | Contract overage / custom plan needed |
| Compliance | Customer terminating + we need to deliver retention obligations |
| CTO + legal | Suspected billing fraud (e.g. tenant abusing trial limits across multiple signups) |

## Related

- `billing-plans-quotas.md` — full plan matrix
- `tenant-offboarding.md` — what to do when a customer churns
- `incident-response.md` — when a billing-affecting incident triggers SLA credits
