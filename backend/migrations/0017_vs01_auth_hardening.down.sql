-- Reverses 0017_vs01_auth_hardening.up.sql.
ALTER TABLE tenant_settings DROP COLUMN IF EXISTS slack_channel;
ALTER TABLE tenant_settings DROP COLUMN IF EXISTS contact_email;

DROP POLICY IF EXISTS evidence_tenant_isolation ON finding_evidence;
DROP POLICY IF EXISTS assets_tenant_isolation   ON assets;
DROP POLICY IF EXISTS findings_tenant_isolation ON findings;
DROP FUNCTION IF EXISTS vaultscan_current_tenant_id();

ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count;

DROP TABLE IF EXISTS token_revocations CASCADE;
DROP TABLE IF EXISTS login_events       CASCADE;
