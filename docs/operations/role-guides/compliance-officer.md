# Compliance Officer guide

**Primary objective:** evidence the platform meets the contracted
controls (SOC2 / ISO27001 / PCI DSS / HIPAA / GDPR); generate
audit-ready packs on demand.

## What's automated

The cron-runner's `compliance_evaluate` task (every 6h):
- Walks every `compliance_controls` row
- Evaluates the control's `evidence_query` against current platform
  state
- Writes the result into `compliance_evidence` with a verdict
  (`pass` / `fail` / `manual`)
- Emits `compliance.evaluated` audit events

What this means: the dashboards are CURRENT to within 6 hours.

## Frameworks pre-mapped

| Framework | Controls | Migrations |
| --- | --- | --- |
| SOC2 (2017) | 15 | 0026 + 0045 |
| ISO 27001 (2022) | 16 | 0026 + 0045 |
| PCI DSS 4.0 | 12 | 0026 + 0045 + 0058 |
| HIPAA (45 CFR 164) | 12 | 0045 |
| NIST CSF 2.0 | 2 | 0026 |
| GDPR (2016/679) | 14 | 0058 |

Per-control mapping: `compliance_controls` table, queried via:
```sql
SELECT framework, framework_version, control_code, title, automation_tier
  FROM compliance_controls
 ORDER BY framework, control_code;
```

## Generating an evidence pack

### Per-engagement compliance report

```bash
# JSON (machine):
curl -s "https://api.<env>/api/v1/compliance/soc2/engagements/$ENG_ID" \
  -H "Authorization: Bearer $TOK" | jq

# Markdown (human; auditors can paste into their working papers):
curl -s "https://api.<env>/api/v1/compliance/soc2/engagements/$ENG_ID.md" \
  -H "Authorization: Bearer $TOK" -o soc2-eng.md
```

The Markdown report includes:
- Engagement metadata (period, scope, authorization)
- Per-control verdict (pass / fail / manual)
- Evidence-supporting query results (counts + sample rows)
- Custody chain proof for each evidence row
- Audit chain integrity verification at report-render time

### Per-tenant rollup

```bash
# Across every framework + every engagement under this tenant:
curl -s "https://api.<env>/api/v1/compliance/tenants/$TENANT_ID/rollup" \
  -H "Authorization: Bearer $TOK" | jq
```

Returns:
```json
{
  "tenant_id": "...",
  "frameworks": {
    "soc2":     {"pass": 12, "fail": 1, "manual": 2,  "coverage": 0.93},
    "iso27001": {"pass": 14, "fail": 0, "manual": 2,  "coverage": 1.00},
    "gdpr":     {"pass":  9, "fail": 1, "manual": 4,  "coverage": 0.93}
  },
  "evaluated_at": "...",
  "audit_chain_verified": true
}
```

### Annual audit pack

```bash
# Full pack: every framework × every active engagement × evidence
# + audit chain export + threat model + data classification.
./tools/scripts/compliance-pack.sh \
  --tenant "$TENANT_ID" \
  --period "2025-01-01:2026-01-01" \
  --frameworks "soc2,iso27001,pci_dss,gdpr" \
  --output /var/lib/vaultscan/audit-packs/$(date +%F)-acme.tgz
```

(If the script isn't yet shipped, the pack is assembled from the per-
engagement reports above + the `audit/export` NDJSON. The shell
wrapper is on the roadmap.)

## DSAR (Data Subject Access Request)

GDPR Article 15 — a data subject asks "what do you have on me?":

```bash
# Generate a per-subject export bundle:
SUBJECT_USER=<user-uuid>
curl -s "https://api.<env>/api/v1/users/$SUBJECT_USER/export" \
  -H "Authorization: Bearer $TOK" \
  > dsar-$(date +%F)-$SUBJECT_USER.json
```

Bundle contents:
- Profile + roles
- Last 90d login events (IP redacted to /24)
- All audit rows where this user was actor OR target
- Notification preferences
- Tenant memberships

## Erasure request (GDPR Article 17)

```bash
curl -X POST "https://api.<env>/api/v1/users/$SUBJECT_USER/erase" \
  -H "Authorization: Bearer $TOK" \
  -d '{"reason":"GDPR Art 17 — subject request 2026-05-18"}'
```

Returns the row-count report. Verify each table is properly
pseudonymised (the integration test `users_erase_test.go` proves
the implementation; the runbook `gdpr-erasure.md` has the audit
queries you run after).

## Custody chain proof

When an auditor asks "prove this finding wasn't tampered with":

```bash
FINDING_ID=<id>

# 1. Get the finding's evidence trail
curl -s "https://api.<env>/api/v1/findings/$FINDING_ID/evidence/chain" \
  -H "Authorization: Bearer $TOK" | jq

# Returns every recorded event: ingested → triaged → assigned →
# remediated → verified, each linked by hash + actor + timestamp.

# 2. Verify the audit chain up to the most recent event
curl -X POST "https://api.<env>/api/v1/audit/verify-deep" \
  -H "Authorization: Bearer $TOK" | jq

# Returns: chain_integrity_ok=true + first_bad_id=NULL.
```

## Evidence integrity

The hourly `evidence_integrity_sample` cron task picks 50 random
evidence blobs, decrypts them, recomputes SHA-256, compares against
the stored hash. Failures increment
`vaultscan_evidence_integrity_failures_total`.

Auditors can ask for the test results:
```bash
curl -s "https://api.<env>/api/v1/evidence/integrity-history?since=2025-01-01" \
  -H "Authorization: Bearer $TOK" | jq
```

(If the endpoint isn't yet exposed, the data is in
`audit_logs WHERE event = 'evidence.integrity_verified'`.)

## What you produce for auditors

| Artifact | How |
| --- | --- |
| Control mapping | Per-framework Markdown report (above) |
| Per-finding chain-of-custody | Evidence chain endpoint (above) |
| Audit chain integrity attestation | verify-deep result + TSA anchor history |
| Encryption-at-rest attestation | tenant_data_keys versions + rotation cadence |
| Encryption-in-transit attestation | TLS config in `infra/helm/.../ingress.yaml` + cipher policy |
| Access control attestation | Permission matrix (`docs/operations/role-guides/permission-matrix.md`) |
| Background-task cadence | cron-runner job list + run frequency |
| Backup + DR | `restore-verify-drill.md` last-run timestamp + result |
| Pentest evidence | `pentest-engagement-runbook.md` final + re-test reports |
| Data residency attestation | tenants.data_region + tenant_residency_history |

## Honest limitations

The platform automates a lot, but not everything an auditor needs is
machine-evidenceable:

- **Organisational policies** — `data-classification.md`,
  `threat-model.md`, the incident-response runbook are evidence of
  POLICY existing; the AUDITOR still verifies they're followed
- **Physical security** — entirely the cloud provider's
  responsibility; you point auditors at AWS / GCP / Azure SOC2
  reports
- **Employee training records** — separate HR system
- **Vendor management** — separate procurement tooling
- **Customer-side controls** — out of scope; the customer evidences
  their own

## Calendar

| Month | What |
| --- | --- |
| Quarterly | Pull per-tenant compliance rollup; share with CSM |
| Annually (Q1) | SOC 2 Type II auditor engagement |
| Annually (Q3) | ISO 27001 surveillance audit |
| Per-customer-contract | DPA review + sign-off |
| Per-incident | Determine regulator notification obligations |

## When to engage external counsel

- DSAR you can't fulfil within 30 days
- Suspected breach involving PHI / cardholder data / EU personal data
- Customer wants a custom DPA clause
- Regulator inquiry
- Sub-processor change (we add a new vendor handling P0/P1 data)

## Related

- `compliance-audit-pack.md` — operator-side evidence assembly
- `compliance-audit-prep.md` — pre-audit checklist
- `gdpr-erasure.md` — Art 17 procedure
- `threat-model.md` — what we threat-modelled
- `data-classification.md` — sensitivity matrix
- `pentest-engagement-runbook.md` — red-team engagement procedure
