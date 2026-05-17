-- 0050_scan_jobs_idempotency.down.sql
DROP INDEX IF EXISTS scan_jobs_tenant_idempotency_key_idx;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS idempotency_key;
