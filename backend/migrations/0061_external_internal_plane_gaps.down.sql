-- 0061_external_internal_plane_gaps.down.sql — reverses 0061.

DROP TABLE IF EXISTS billing_usage_adjustments;
DROP TABLE IF EXISTS partner_plan_history;

DROP POLICY IF EXISTS compliance_rollup_snapshots_tenant_isolation ON compliance_rollup_snapshots;
ALTER TABLE compliance_rollup_snapshots NO FORCE ROW LEVEL SECURITY;
ALTER TABLE compliance_rollup_snapshots DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS compliance_rollup_snapshots;

DROP TABLE IF EXISTS tenant_partner_migrations;

DROP INDEX IF EXISTS tenants_quarantined_idx;
ALTER TABLE tenants
    DROP COLUMN IF EXISTS quarantine_started_at,
    DROP COLUMN IF EXISTS quarantine_initiated_by,
    DROP COLUMN IF EXISTS quarantine_reason;

DROP TABLE IF EXISTS support_impersonation_sessions;

DROP POLICY IF EXISTS tenant_scim_tokens_tenant_isolation ON tenant_scim_tokens;
ALTER TABLE tenant_scim_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_scim_tokens DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS tenant_scim_tokens;

DROP POLICY IF EXISTS tenant_sso_config_tenant_isolation ON tenant_sso_config;
ALTER TABLE tenant_sso_config NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_sso_config DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS tenant_sso_config;

DROP TABLE IF EXISTS plan_change_requests;
