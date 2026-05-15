-- 0042 — Partition management infrastructure (NOT a destructive
-- conversion).
--
-- Ships a SQL function `vaultscan_ensure_month_partition(table, month)`
-- that the cron-runner calls monthly to pre-create partitions for the
-- next month + drop the oldest partition if a tenant retention
-- window says to.
--
-- The actual conversion of audit_logs / findings / scan_jobs from
-- flat tables to partitioned ones is a one-shot operator task — see
-- docs/operations/database-partitioning.md. We ship the helper here
-- so production deployments that have already done the conversion
-- can use it.
--
-- Why not auto-convert? Recreating tables with PARTITION BY requires
-- temporarily holding ACCESS EXCLUSIVE locks on tables that hold the
-- audit chain, the evidence references, and active scan jobs.
-- Production deployments do this in a maintenance window with the
-- application stopped.

BEGIN;

-- ---- Ensure partition for a month ----------------------------------------
--
-- Creates table <prefix>_y<YYYY>m<MM> as a partition of <prefix> for
-- the calendar month containing `target_month`. Idempotent — already
-- existing partitions are silently skipped.
--
-- Usage:
--   SELECT vaultscan_ensure_month_partition('audit_logs', now() + interval '1 month');
--
-- The helper:
--   1. Confirms <prefix> is actually partitioned (otherwise no-op).
--   2. Computes the (start, end) timestamptz range for the month.
--   3. Issues CREATE TABLE ... PARTITION OF ... FOR VALUES FROM (..) TO (..).

CREATE OR REPLACE FUNCTION vaultscan_ensure_month_partition(
    parent_table TEXT,
    target_month TIMESTAMPTZ
) RETURNS TEXT AS $$
DECLARE
    pname TEXT;
    p_start TIMESTAMPTZ;
    p_end   TIMESTAMPTZ;
    is_partitioned BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
          JOIN pg_class c ON c.oid = pt.partrelid
         WHERE c.relname = parent_table
    ) INTO is_partitioned;

    IF NOT is_partitioned THEN
        RETURN format('skipped: %s is not partitioned', parent_table);
    END IF;

    p_start := date_trunc('month', target_month);
    p_end   := p_start + interval '1 month';
    pname := format('%s_y%sm%s', parent_table,
        to_char(p_start, 'YYYY'), to_char(p_start, 'MM'));

    -- Skip if already exists.
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = pname) THEN
        RETURN format('exists: %s', pname);
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        pname, parent_table, p_start, p_end);

    RETURN format('created: %s [%s..%s)', pname, p_start, p_end);
END;
$$ LANGUAGE plpgsql;

-- ---- Drop partitions older than a retention boundary ---------------------
--
-- Detaches (NOT drops) the partition so the data survives in the
-- archive table until ops moves it to cold storage / S3.

CREATE OR REPLACE FUNCTION vaultscan_detach_old_partitions(
    parent_table TEXT,
    older_than   TIMESTAMPTZ
) RETURNS SETOF TEXT AS $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN
        SELECT child.relname AS pname,
               (regexp_match(child.relname, '^' || parent_table || '_y(\d{4})m(\d{2})$'))[1] AS y,
               (regexp_match(child.relname, '^' || parent_table || '_y(\d{4})m(\d{2})$'))[2] AS m
          FROM pg_inherits inh
          JOIN pg_class child  ON child.oid  = inh.inhrelid
          JOIN pg_class parent ON parent.oid = inh.inhparent
         WHERE parent.relname = parent_table
    LOOP
        IF rec.y IS NULL OR rec.m IS NULL THEN
            CONTINUE;
        END IF;
        IF make_date(rec.y::int, rec.m::int, 1)::timestamptz < older_than THEN
            EXECUTE format('ALTER TABLE %I DETACH PARTITION %I',
                parent_table, rec.pname);
            RETURN NEXT format('detached: %s', rec.pname);
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

COMMIT;
