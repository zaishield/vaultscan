# Data Residency Pin Runbook

How to set, enforce, and verify a tenant's data-residency commitment.

## Background

Many enterprise contracts include a clause along the lines of "Customer
Data shall be stored and processed exclusively within the European
Economic Area". VaultScan supports this via a per-tenant pin in the
`tenants.data_region` column (added in migration 0055).

Allowed region codes: `ae | eu | uk | in | us | sg | au | jp`.

## Enforcement model

Every backend pod reads `VAULTSCAN_REGION` at startup. When a tenant
is pinned, the following write paths refuse the operation with HTTP
451 (Unavailable For Legal Reasons):

| Path                            | Service method                  |
| ------------------------------- | ------------------------------- |
| POST /api/v1/scans              | scanorch.Submit                 |
| POST /api/v1/assets             | assets.Create                   |
| evidence Record (internal)      | evidence.RecordWithDEK          |

If `VAULTSCAN_REGION` is unset on the pod, the check no-ops. Single-
region deployments may legitimately run without a region pin — the
constraint is that EVERY pod across a multi-region deployment must
have it set, otherwise the cross-region pod becomes a residency hole.

## Setting a pin

```bash
curl -X PUT "https://api.vaultscan.zaishield.com/api/v1/tenants/${TID}/residency" \
  -H "Authorization: Bearer ${OPERATOR_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"region": "eu", "reason": "Master Services Agreement §4.2"}'
```

Empty region clears the pin:

```bash
curl -X PUT "..." -d '{"region": "", "reason": "tenant requested removal of pin"}'
```

## Verification

```sql
SELECT id, name, data_region FROM tenants WHERE id = '<tid>';

-- Audit trail
SELECT changed_at, from_region, to_region, actor_id, reason
  FROM tenant_residency_history
 WHERE tenant_id = '<tid>'
 ORDER BY changed_at DESC;
```

## Operator-side: making a pod region-aware

In Helm `values.yaml`:

```yaml
api:
  env:
    - name: VAULTSCAN_REGION
      value: "eu"

scanner-worker:
  region: eu     # already in chart
  env:
    - name: VAULTSCAN_REGION
      value: "eu"
```

The scanner-worker chart already templates this; the API and
agent-gateway deployments need it added once per regional cluster.

## Multi-region routing

A tenant pinned to `eu` MUST be served only by pods that have
`VAULTSCAN_REGION=eu`. Typical patterns:

- DNS-based: `api-eu.vaultscan.zaishield.com` resolves to the eu
  cluster; the customer's DNS / proxy is configured to use that.
- Path-based: a global router inspects the JWT's tenant_id, looks
  up `data_region`, and proxies. The cross-region check at the
  service layer catches misrouted requests with 451.

## When a 451 fires

The portal displays:

> Your data is pinned to region `<X>`. Please route your request via
> `api-<X>.vaultscan.zaishield.com`.

Operator inspection:

```sql
SELECT t.id, t.data_region, COUNT(al.id) AS denied
  FROM tenants t
  JOIN audit_logs al ON al.tenant_id = t.id
 WHERE al.event LIKE 'residency.violation%'
   AND al.occurred_at > now() - INTERVAL '24 hours'
 GROUP BY t.id, t.data_region
 ORDER BY denied DESC;
```

(The 451 path doesn't write a separate audit row today — the violation
is visible in the request log + the 451 response. If you need a
dedicated audit event, file a follow-up; the service-layer method
returns a typed error so wiring an audit emit is cheap.)
