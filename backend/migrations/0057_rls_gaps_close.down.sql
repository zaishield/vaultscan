-- 0057_rls_gaps_close.down.sql
-- Reverses migration 0057 cleanly so a rollback doesn't leave the
-- database in a half-locked state.

-- ---- CHECK constraints ----------------------------------------------
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_severity_check;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_status_check;

-- ---- Indexes --------------------------------------------------------
DROP INDEX IF EXISTS audit_logs_chain_tail_idx;
DROP INDEX IF EXISTS audit_logs_tenant_event_occurred_idx;
DROP INDEX IF EXISTS scan_jobs_tenant_status_created_idx;
DROP INDEX IF EXISTS findings_tenant_status_created_idx;

-- ---- RLS policies + force-row-level-security -----------------------
-- DROP POLICY first (FORCE RLS only matters if policies exist).
DROP POLICY IF EXISTS idempotency_keys_tenant_isolation         ON idempotency_keys;
ALTER TABLE idempotency_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dashboard_sse_subscriptions_tenant_isolation ON dashboard_sse_subscriptions;
ALTER TABLE dashboard_sse_subscriptions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE dashboard_sse_subscriptions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS compliance_evidence_tenant_isolation      ON compliance_evidence;
ALTER TABLE compliance_evidence NO FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence DISABLE ROW LEVEL SECURITY;
