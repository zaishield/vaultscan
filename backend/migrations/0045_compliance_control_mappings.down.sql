BEGIN;
DROP POLICY IF EXISTS compliance_evidence_tenant_isolation ON compliance_evidence;
DROP INDEX IF EXISTS compliance_evidence_latest_idx;
DROP TABLE IF EXISTS compliance_evidence;
DROP INDEX IF EXISTS compliance_controls_framework_idx;
DROP TABLE IF EXISTS compliance_controls;
COMMIT;
