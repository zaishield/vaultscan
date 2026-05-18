# Billing plans + quotas

The internal pricing + quota matrix VaultScan ships with. Operators
override per customer via the platform-admin API.

## Plans

| Plan | Tenants | Users / tenant | Scans / month | Findings retention | Evidence retention | Cost (USD/mo) |
| --- | --- | --- | --- | --- | --- | --- |
| Trial          | 1   | 5      | 100        | 30 days | 30 days  | 0 |
| Starter        | 1   | 25     | 1,000      | 1 year  | 1 year   | 500 |
| Team           | 5   | 100    | 10,000     | 3 years | 3 years  | 2,500 |
| Business       | 25  | 500    | 50,000     | 5 years | 5 years  | 10,000 |
| Enterprise     | 100 | 5,000  | 250,000    | 7 years | 7 years  | 40,000 |
| Enterprise+    | ∞   | ∞      | Negotiated | 7 years | 7 years (WORM) | Contract |

## Per-plan feature gates

| Feature | Trial | Starter | Team | Business | Ent | Ent+ |
| --- | --- | --- | --- | --- | --- | --- |
| Scanner tools, all 27 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Mobile sidecar | – | – | ✓ | ✓ | ✓ | ✓ |
| SAML SSO | – | – | ✓ | ✓ | ✓ | ✓ |
| SCIM provisioning | – | – | – | ✓ | ✓ | ✓ |
| MFA enforcement | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Custom roles | – | – | ✓ | ✓ | ✓ | ✓ |
| White-label branding | – | – | – | ✓ | ✓ | ✓ |
| Data residency pin | – | – | – | ✓ | ✓ | ✓ |
| Dedicated tenant isolation | – | – | – | – | ✓ | ✓ |
| HIPAA BAA | – | – | – | – | ✓ | ✓ |
| Custom DPA | – | – | – | – | – | ✓ |
| Premium support | – | – | 9x5 | 24x5 | 24x7 | 24x7 + named TAM |
| SLA credits | – | – | 99.5% | 99.9% | 99.95% | Custom |
| Pentest evidence pack | – | – | – | – | ✓ | ✓ |

## Rate limits per plan

| Plan | API RPS (per tenant) | Concurrent scans | Inbound webhook RPM |
| --- | --- | --- | --- |
| Trial          | 10  | 1   | 60   |
| Starter        | 50  | 3   | 300  |
| Team           | 200 | 10  | 1,200 |
| Business       | 500 | 25  | 6,000 |
| Enterprise     | 2,000 | 100 | 30,000 |
| Enterprise+    | Custom | Custom | Custom |

Limits enforced by:
- API: `middleware.RateLimit` + `middleware.TenantRateLimit`
- Scans: scanner-worker dispatch checks per-tenant active count
- Webhooks: per-IP authLimiter + per-tenant quota in scan_jobs flow

## Quota enforcement

Hard caps return:
- HTTP `429 Too Many Requests` for rate-limit hits (with `Retry-After`)
- HTTP `402 Payment Required` for plan-quota hits (scans/month, users, etc.)
- HTTP `503 Service Unavailable` for infra constraints

Soft warnings (>80% utilisation) emit `quota.warning` audit events
that integrations can forward to the customer.

## Configuring a tenant's plan

Programmatic (platform-admin):

```bash
curl -X PUT "$API/api/v1/partners/$PARTNER_ID/billing/plan" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"plan":"enterprise","custom_overrides":{"concurrent_scans":150}}'
```

Inspect:

```bash
curl -s "$API/api/v1/partners/$PARTNER_ID/billing/usage" \
  -H "Authorization: Bearer $ADMIN_JWT" | jq
```

## Internal cost model

Per-tenant infrastructure cost the operator should benchmark against:

| Plan | DB usage (GiB-mo) | Object store (GiB-mo) | API CPU (vCPU-mo) | Total infra cost @ AWS list |
| --- | --- | --- | --- | --- |
| Trial          | 0.5 | 0.5  | 0.05 | ~$3 |
| Starter        | 5   | 5    | 0.5  | ~$30 |
| Team           | 50  | 100  | 5    | ~$300 |
| Business       | 250 | 1,000 | 25  | ~$1,500 |
| Enterprise     | 1,500 | 10,000 | 150 | ~$8,000 |

The customer-facing price MUST be >3x infra cost to cover ops, R&D,
support, sales. Margins below 3x indicate the plan is undersized.

## Billing cycle

- Daily: usage rollup (`billing.daily_rollup` cron task)
- Monthly: invoice generation + Stripe charge (1st of month)
- Quarterly: customer plan review (account team)
- Annually: pricing review (product + finance)

## Customer-facing pricing page

Pricing displayed at `https://zaishield.com/pricing` is the source of
truth for customer-facing terms. This doc is the engineering-facing
canonical — divergence between this doc and the website is a
go-to-market bug; raise immediately.

## Related

- `internal/billing/` — service code
- `migrations/0023_billing_plans.up.sql` — schema
- `capacity-planning.md` — what each plan costs to serve
