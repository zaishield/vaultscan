# Database Partitioning Conversion (one-shot)

## When to do this

Convert flat tables to declarative partitions when **any** of the
following becomes true for a tenant:

| Table        | Threshold (rows) |
|--------------|------------------|
| `audit_logs` | 10,000,000       |
| `findings`   |  5,000,000       |
| `scan_jobs`  |  5,000,000       |
| `bus_events` | 50,000,000       |

Below those thresholds the single-table layout is fine and conversion
isn't worth the maintenance window.

## What ships in-tree

Migration `0042_partition_management.up.sql` adds two helpers:

- `vaultscan_ensure_month_partition(parent, target_month)` — idempotent
  CREATE PARTITION OF for the calendar month containing `target_month`.
  Returns 'created: <name>' / 'exists: <name>' / 'skipped: <parent> is
  not partitioned'.
- `vaultscan_detach_old_partitions(parent, older_than)` — DETACH (not
  DROP) partitions older than the cutoff so an archive job can move
  the data to S3 before final removal.

The cron-runner calls `vaultscan_ensure_month_partition` every 6 hours
for the four candidate tables (current + next + month-after). On
unconverted tables this is a no-op.

## The conversion procedure (per table)

DOWNTIME REQUIRED: ~5 min × table for a 100M-row table on
moderate hardware. Schedule in your maintenance window.

Example for `audit_logs`:

```sql
BEGIN;

-- 1. Rename the existing flat table.
ALTER TABLE audit_logs RENAME TO audit_logs_legacy;

-- 2. Create the partitioned shell. Schema MUST exactly match
--    audit_logs_legacy; the easiest way to capture the current
--    schema is to dump it via pg_dump --schema-only --table=audit_logs
--    and copy it here. The PRIMARY KEY MUST include the partition
--    key column.
CREATE TABLE audit_logs (
    id            BIGSERIAL    NOT NULL,
    -- ... (all other columns from audit_logs_legacy) ...
    occurred_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- 3. Create monthly partitions covering the legacy data range +
--    the next 3 months.
SELECT vaultscan_ensure_month_partition('audit_logs', g.month)
  FROM generate_series(
    (SELECT date_trunc('month', min(occurred_at)) FROM audit_logs_legacy),
    (SELECT date_trunc('month', now() + interval '3 months')),
    interval '1 month') AS g(month);

-- 4. Default partition catches anything outside the explicit ranges.
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

-- 5. Move the data.
INSERT INTO audit_logs (id, ..., occurred_at)
  SELECT id, ..., occurred_at FROM audit_logs_legacy;

-- 6. Re-create indexes (declared on the parent — auto-applies to
--    every partition).
CREATE INDEX audit_logs_tenant_idx ON audit_logs (tenant_id, occurred_at DESC);
CREATE INDEX audit_logs_event_idx  ON audit_logs (event,     occurred_at DESC);

-- 7. Re-attach RLS policies.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE  ROW LEVEL SECURITY;
CREATE POLICY audit_logs_tenant_isolation ON audit_logs ...;

-- 8. Drop the legacy table.
DROP TABLE audit_logs_legacy CASCADE;

-- 9. Reset the sequence so new inserts continue from where legacy left off.
SELECT setval('audit_logs_id_seq', COALESCE((SELECT max(id) FROM audit_logs), 1));

COMMIT;
```

## Verification

After conversion:

```sql
-- Confirm parent is partitioned.
SELECT parttype FROM pg_partitioned_table WHERE partrelid = 'audit_logs'::regclass;
-- 'r' = range partitioning ✓

-- List partitions.
SELECT child.relname
  FROM pg_inherits inh
  JOIN pg_class child  ON child.oid  = inh.inhrelid
  JOIN pg_class parent ON parent.oid = inh.inhparent
 WHERE parent.relname = 'audit_logs'
 ORDER BY 1;

-- Sanity: row counts match.
SELECT count(*) FROM audit_logs;
```

## Rollback

If something goes wrong mid-conversion, the legacy table is still
present until step 8. Roll back by:

1. `DROP TABLE audit_logs CASCADE;` — drops the partitioned parent
   and all partitions.
2. `ALTER TABLE audit_logs_legacy RENAME TO audit_logs;` — restore
   the original flat table.
3. Re-create indexes/policies on the restored table.

## Archival of detached partitions

A monthly archival job (separate from `partition_maintenance` in the
cron-runner) runs:

```sql
-- Detach partitions older than 13 months.
SELECT vaultscan_detach_old_partitions('audit_logs', now() - interval '13 months');
```

The detached tables become standalone — `pg_dump` them, ship to
`s3://vaultscan-archive/audit_logs/<year>/<month>/`, then `DROP TABLE`
locally. Detached partitions still appear in `pg_class` until dropped,
so monitor disk usage and prune.

## Why monthly (not daily/yearly)

- **Monthly** matches our retention windows (most policies are 6/12/24
  months).
- **Daily** would create 365 partitions/year; planner overhead grows
  with partition count.
- **Yearly** loses the range-pruning win for the most common query
  ("last 30 days").

## Production checklist

- [ ] Schema-only `pg_dump` of the flat table captured in the runbook PR.
- [ ] `EXPLAIN ANALYZE` of the top 5 hot queries against a copy of
      production, before AND after conversion, attached to the change
      ticket.
- [ ] Maintenance window booked + customer comms sent (>= 2h advance).
- [ ] Sentry / PagerDuty silenced for the maintenance window.
- [ ] Restore-verify drill (`docs/operations/restore-verify-drill.md`)
      confirmed green within 24h before the change.
- [ ] Runbook reviewer signed off.
