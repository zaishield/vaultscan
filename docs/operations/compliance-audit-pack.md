# Compliance Audit Pack

Closes SEV-3.7 from the forensic report: the §22 dashboard previously
rendered generic finding severity counts. Auditors got a number.
Now they get a control-by-control walk-through across four frameworks:

| Framework        | Version          | Controls mapped |
|------------------|------------------|-----------------|
| SOC 2 TSC        | 2017 rev. 2022   | 12              |
| ISO/IEC 27001    | 2022 Annex A     | 12              |
| PCI-DSS          | 4.0              | 12              |
| HIPAA Security   | 45 CFR 164.30x   | 12              |

48 controls total. Each row in `compliance_controls` carries:

- `control_code` — the citable identifier (CC6.1, A.5.15, 10.5.1,
  164.312(a)(1))
- `title` + `description` — what the auditor asks about
- `evidence_query` — the tiny DSL string that
  `compliance.Evaluator` runs to produce a verdict
- `automation_tier` — `automated` | `semi_automated` | `manual`

The evaluator writes a row into `compliance_evidence` per (tenant,
control) every 6 hours (cron job `compliance_evaluate`).

## Query DSL

| Verb               | Filters                                  | Example                                                       |
|--------------------|------------------------------------------|---------------------------------------------------------------|
| `findings:`        | status, severity, age, window            | `findings:status=open,severity>=high,age>30d`                 |
| `audit_logs:`      | event, event_prefix, actor_type, window  | `audit_logs:event=UserAuthSucceeded,actor_type=user,window=30d` |
| `scan_jobs:`       | plane, status, profile_code, window      | `scan_jobs:plane=internal,status=succeeded,window=90d`        |
| `evidence:`        | encrypted, worm_enabled                  | `evidence:encrypted=true,worm_enabled=true`                   |
| `retention:`       | event_prefix, retention_days             | `retention:event_prefix=*,retention_days>=365`                |
| `integrations:`    | type, enabled                            | `integrations:type=siem,enabled=true`                         |
| `cloud_posture:`   | provider, window                         | `cloud_posture:provider=aws,verdict=pass,window=7d`           |
| `tenant_data_keys:`| —                                        | `tenant_data_keys:kek_version>0`                              |
| `audit_archive_runs:` | window                                | `audit_archive_runs:tsa_token IS NOT NULL,window=30d`         |
| `audit_tsa_anchors:`  | window                                | `audit_tsa_anchors:window=24h`                                |
| `manual:`          | (free-form note)                         | `manual:reviewer-attests-ir-plan-current`                     |

Adding a new control = one `INSERT` into `compliance_controls`. No
code change unless you need a new verb.

## Verdict rules

| Verb               | Rule                                                          |
|--------------------|---------------------------------------------------------------|
| findings + status=open | ANY hit = fail; 0 = pass                                  |
| findings + status=resolved | ≥1 = pass; 0 = fail                                  |
| audit_logs + chain_integrity=true | runs VerifyDeep-equivalent CTE                |
| audit_logs (other) | ≥1 in window = pass (we expect activity)                      |
| scan_jobs          | ≥1 succeeded scan in window = pass                            |
| evidence           | ≥1 row matching = pass                                        |
| retention          | configured max ≥ floor = pass                                 |
| integrations       | ≥1 enabled of `type` = pass                                   |
| cloud_posture      | ≥1 snapshot in window = pass                                  |
| tenant_data_keys   | ≥1 wrapped DEK exists = pass                                  |
| audit_archive_runs | ≥1 archive with TSA token in window = pass                    |
| audit_tsa_anchors  | ≥1 anchor in window = pass                                    |
| manual             | always returns `manual` — requires human attestation          |

## Reading the dashboard

The frontend's existing `/compliance` page can now query:

```sql
SELECT
  c.framework, c.framework_version, c.control_code, c.title,
  c.automation_tier,
  ev.verdict, ev.observed_count, ev.note, ev.observed_at
FROM compliance_controls c
LEFT JOIN LATERAL (
  SELECT verdict, observed_count, note, observed_at
    FROM compliance_evidence
   WHERE tenant_id = $1 AND control_id = c.id
   ORDER BY observed_at DESC LIMIT 1
) ev ON true
WHERE c.framework = $2
ORDER BY c.control_code;
```

Auditors typically want one PDF per framework. The export endpoint
(future) flattens the above into a structured document with the
evidence query, the observed count, the verdict, and the timestamp.

## Producing an audit pack ZIP

The standard SOC 2 / ISO audit prep involves bundling:

1. `controls.csv` — every row from `compliance_controls`.
2. `evidence-latest.csv` — most-recent `compliance_evidence` row per
   (tenant, control).
3. `audit_archive_runs.csv` — proof of retention + RFC 3161 anchors.
4. `tsa-tokens/` — the actual `tsa_token` blobs (one per archive row).
5. `screenshots/` — manual artifacts (policy docs, IR plan, etc.).

The export script lives in `backend/cmd/audit-pack/` (future
deliverable). For now, ops can produce the first three via psql:

```bash
psql -c "\copy (SELECT * FROM compliance_controls) TO 'controls.csv' CSV HEADER"
psql -c "\copy (SELECT DISTINCT ON (control_id) * FROM compliance_evidence
                WHERE tenant_id='<id>' ORDER BY control_id, observed_at DESC) TO 'evidence.csv' CSV HEADER"
psql -c "\copy audit_archive_runs TO 'archive-runs.csv' CSV HEADER"
```

## Why not just buy Drata / Vanta / Secureframe?

You still might — those tools add policy-evidence collection (HR
records, Apple MDM enrollment) we don't cover. But the *technical*
evidence layer (encryption-at-rest is enabled, audit logs are
unbroken, vulnerability scans run on schedule, retention is enforced)
should live in the platform that does the security work; bouncing it
through a third-party SaaS adds drift + latency. This table answers
"is the platform compliant" directly from operational data.
