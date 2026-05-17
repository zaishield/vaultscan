-- 0050_scan_jobs_idempotency.up.sql
--
-- Caller-supplied idempotency key on scan_jobs. Internal callers
-- (retesting.LaunchScan) and API clients that want exactly-once
-- semantics across retries pass the key in SubmitInput; the
-- orchestrator returns the pre-existing job rather than creating
-- a duplicate. UNIQUE per tenant — different tenants happen to
-- pick the same UUID? fine, they're isolated.

ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS scan_jobs_tenant_idempotency_key_idx
    ON scan_jobs(tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
