# Restore-Verify Drill (HS-03 follow-up)

## What

A nightly Kubernetes CronJob that pulls the most-recent VAULTSCAN
backup from object storage, restores it into a throwaway Postgres
running as a sidecar in the same pod, runs the audit-chain verifier,
and exits non-zero on any failure.

**Why it matters:** without this, backup health is opinion not fact.
Restoring once a quarter is too slow to catch corruption introduced by:

- Schema drift from a missed migration on the dump host.
- A `pg_dump --exclude-table` that silently drops something later
  required by the schema.
- S3 bucket policy changes that block `aws s3 cp`.
- A backup container that exits 0 but uploaded a 0-byte file.

## How to enable

Set in your environment-specific `values.yaml`:

```yaml
backup:
  enabled: true
  # ... existing backup config ...

restoreVerify:
  enabled: true
  schedule: "0 4 * * *"
```

## What gets verified

1. **Latest backup exists** — `aws s3 ls` returns at least one
   timestamped object. Failure → exit 2.
2. **Backup decompresses + restores** — `gunzip | pg_restore` against
   the sandbox Postgres. Failure → exit 1 (pg_restore's own code).
3. **Schema sanity** — `audit_logs` row count > 0. Failure → exit 3.
4. **Audit chain integrity** — recursive CTE replicates
   `audit.Service.VerifyDeep` against the restored data. Any row whose
   computed hash doesn't match the stored hash → exit 4.

## Alerts

Add to your Prometheus AlertManager rules:

```yaml
groups:
  - name: vaultscan-restore-verify
    rules:
      - alert: VaultscanRestoreVerifyFailed
        expr: |
          kube_job_failed{job_name=~"vaultscan-restore-verify-.*"} > 0
        for: 0m
        annotations:
          summary: "Restore-verify drill failed"
          description: "Backup is unrestorable; investigate immediately"
        labels:
          severity: page
      - alert: VaultscanRestoreVerifyMissing
        expr: |
          time() - kube_cronjob_status_last_successful_time{
            cronjob="vaultscan-restore-verify"
          } > 86400 * 2
        annotations:
          summary: "Restore-verify drill hasn't passed in 48h"
        labels:
          severity: warn
```

## Manual run (debugging)

```bash
kubectl -n vaultscan create job --from=cronjob/vaultscan-restore-verify drill-$(date +%s)
kubectl -n vaultscan logs -f job/drill-<id> -c verifier
kubectl -n vaultscan logs    job/drill-<id> -c sandbox-pg
```

## Pod layout

| container | image | purpose |
|---|---|---|
| sandbox-pg | postgres:16-alpine (fsync=off) | throwaway PG, dies with pod |
| verifier | vaultscan-restore-verify | downloads backup, restores, asserts |

Both containers share the pod's ephemeral `pgdata` volume; nothing is
persisted across runs.

## On-call escalation

1. Page fires → check the verifier container's logs (last 200 lines
   identify which exit code fired).
2. If exit 2 (no backups in S3): the backup CronJob is silently
   failing. Check
   `kubectl get cronjob vaultscan-backup -n vaultscan` for last
   successful run.
3. If exit 4 (audit-chain mismatch): the production audit log is
   tampered or corrupted. Treat as a security incident (see
   `incident-response.md`).
4. If pg_restore fails: schema drift between the dump host and the
   restore sandbox. Check the running migrations match
   `migrations/*.up.sql`.

## SLO

- 95% of nightly runs complete successfully within 30 minutes.
- 99% of failures page on-call within 5 minutes.
- 0 silently-rotted backups (this entire drill exists to enforce that).
