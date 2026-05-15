-- Reverses 0014_findings_ops.up.sql.
DROP INDEX IF EXISTS retest_requests_assignee_idx;
ALTER TABLE retest_requests DROP COLUMN IF EXISTS scan_job_id;

DROP INDEX IF EXISTS evidence_expires_idx;
ALTER TABLE finding_evidence DROP COLUMN IF EXISTS purged_at;

DROP INDEX IF EXISTS findings_breached_idx;
DROP INDEX IF EXISTS findings_due_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS sla_breached_at;
ALTER TABLE findings DROP COLUMN IF EXISTS due_at;

ALTER TABLE assets DROP COLUMN IF EXISTS risk_score;
