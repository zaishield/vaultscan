-- VS-04: asset risk score (composite metric driving dashboards + remediation
-- queues). Recomputed by the findings ingestion path; null until the first
-- finding lands.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_score NUMERIC(6,2) DEFAULT 0;

-- VS-07: finding SLA tracking. due_at is set on insert from
-- tenant_settings.default_severity_sla; sla_breached_at gets stamped by the
-- SLA breach worker when due_at passes without remediation.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS due_at         TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS sla_breached_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS findings_due_idx ON findings(due_at);
CREATE INDEX IF NOT EXISTS findings_breached_idx ON findings(sla_breached_at)
    WHERE sla_breached_at IS NOT NULL;

-- VS-08: evidence vault retention enforcer needs a target the worker can
-- key off. expires_at is already present; add an explicit purged_at marker
-- so deletes are recorded without losing the row (audit trail intact).
ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS evidence_expires_idx ON finding_evidence(expires_at)
    WHERE expires_at IS NOT NULL AND purged_at IS NULL;

-- VS-09: retest_requests links to the scan job that retested it. The schema
-- already has retest_results.scan_job_id; surface it on the parent request
-- so a single SELECT can drive the retest queue UI.
ALTER TABLE retest_requests ADD COLUMN IF NOT EXISTS scan_job_id UUID
    REFERENCES scan_jobs(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS retest_requests_assignee_idx
    ON retest_requests(status)
    WHERE status IN ('pending','assigned','in_progress');
