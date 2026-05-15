-- 0040 — Expand Row Level Security coverage to every tenant-scoped table.
--
-- HS-01 deepening shipped RLS on findings/assets/finding_evidence (the
-- highest-value PII surfaces) at migration 0033. This migration closes
-- the gap by enabling RLS on every other table that has a tenant_id
-- column, so the application's WHERE-clause discipline isn't the sole
-- line of defense against cross-tenant reads/writes.
--
-- Pattern (identical to 0017 for the original three):
--   1. EXECUTE 'DROP POLICY IF EXISTS' to make the migration rerunnable
--   2. CREATE POLICY <table>_tenant_isolation ON <table>
--        FOR ALL TO PUBLIC
--        USING (vaultscan_current_tenant_id() IS NULL
--               OR tenant_id = vaultscan_current_tenant_id())
--   3. ALTER TABLE <table> ENABLE ROW LEVEL SECURITY
--   4. ALTER TABLE <table> FORCE ROW LEVEL SECURITY
--
-- The NULL-tenant branch keeps platform/cross-tenant service paths
-- (analytics-worker, cosign verifier, super-admin) working — they
-- explicitly do NOT call db.SetTenantContext. HTTP middleware that
-- handles tenant-scoped traffic sets the GUC on every request.
--
-- Tables INTENTIONALLY excluded (no tenant_id column, or platform-scope):
--   - users (carries tenant_id but is read pre-context by login flow)
--   - audit_logs (read by platform admin tooling that bypasses RLS)
--   - admin_actions (platform-scope)
--   - ct_log_entries (platform-scope CT log)
--   - bus_events (durable transport, read by platform consumers)
--   - partner_customer_mapping (read by partner-level views)
--   - external_data_sources (catalog table)
--
-- The remaining tables (16) get RLS below.

BEGIN;

-- Reusable DO block to drop any prior copies of the policies we're
-- about to create. Splitting per-table because PL/pgSQL DO blocks
-- can't take parameters — at this scale, inline is clearer than a
-- helper function.
DO $$
DECLARE
  t TEXT;
  policies TEXT[] := ARRAY[
    'engagements_tenant_isolation ON engagements',
    'scan_jobs_tenant_isolation ON scan_jobs',
    'agents_tenant_isolation ON agents',
    'integrations_tenant_isolation ON integrations',
    'reports_tenant_isolation ON reports',
    'report_schedules_tenant_isolation ON report_schedules',
    'tenant_branding_tenant_isolation ON tenant_branding',
    'tenant_settings_tenant_isolation ON tenant_settings',
    'tenant_data_keys_tenant_isolation ON tenant_data_keys',
    'clients_tenant_isolation ON clients',
    'cloud_accounts_tenant_isolation ON cloud_accounts',
    'notification_channels_tenant_isolation ON notification_channels',
    'retest_batches_tenant_isolation ON retest_batches',
    'marketplace_installs_tenant_isolation ON marketplace_installs',
    'customer_feedback_tenant_isolation ON customer_feedback',
    'finding_clusters_tenant_isolation ON finding_clusters',
    'finding_severity_overrides_tenant_isolation ON finding_severity_overrides',
    'finding_suppression_rules_tenant_isolation ON finding_suppression_rules',
    'scope_decision_logs_tenant_isolation ON scope_decision_logs',
    'user_dashboard_layouts_tenant_isolation ON user_dashboard_layouts'
  ];
BEGIN
  FOREACH t IN ARRAY policies LOOP
    BEGIN
      EXECUTE 'DROP POLICY IF EXISTS ' || t;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
END $$;

-- engagements
CREATE POLICY engagements_tenant_isolation ON engagements
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagements FORCE  ROW LEVEL SECURITY;

-- scan_jobs
CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE  ROW LEVEL SECURITY;

-- agents
CREATE POLICY agents_tenant_isolation ON agents
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE  ROW LEVEL SECURITY;

-- integrations
CREATE POLICY integrations_tenant_isolation ON integrations
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations FORCE  ROW LEVEL SECURITY;

-- reports
CREATE POLICY reports_tenant_isolation ON reports
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE  ROW LEVEL SECURITY;

-- report_schedules
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='report_schedules') THEN
    EXECUTE 'CREATE POLICY report_schedules_tenant_isolation ON report_schedules
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE report_schedules FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- tenant_branding
CREATE POLICY tenant_branding_tenant_isolation ON tenant_branding
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding FORCE  ROW LEVEL SECURITY;

-- tenant_settings
CREATE POLICY tenant_settings_tenant_isolation ON tenant_settings
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_settings FORCE  ROW LEVEL SECURITY;

-- tenant_data_keys (per-tenant DEKs — MUST be RLS-locked)
CREATE POLICY tenant_data_keys_tenant_isolation ON tenant_data_keys
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE tenant_data_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_data_keys FORCE  ROW LEVEL SECURITY;

-- clients
CREATE POLICY clients_tenant_isolation ON clients
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients FORCE  ROW LEVEL SECURITY;

-- cloud_accounts
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='cloud_accounts') THEN
    EXECUTE 'CREATE POLICY cloud_accounts_tenant_isolation ON cloud_accounts
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE cloud_accounts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE cloud_accounts FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- notification_channels
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='notification_channels') THEN
    EXECUTE 'CREATE POLICY notification_channels_tenant_isolation ON notification_channels
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE notification_channels FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- retest_batches
CREATE POLICY retest_batches_tenant_isolation ON retest_batches
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE retest_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE retest_batches FORCE  ROW LEVEL SECURITY;

-- marketplace_installs
CREATE POLICY marketplace_installs_tenant_isolation ON marketplace_installs
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
ALTER TABLE marketplace_installs ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_installs FORCE  ROW LEVEL SECURITY;

-- customer_feedback
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='customer_feedback') THEN
    EXECUTE 'CREATE POLICY customer_feedback_tenant_isolation ON customer_feedback
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE customer_feedback ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE customer_feedback FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- finding_clusters
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='finding_clusters') THEN
    EXECUTE 'CREATE POLICY finding_clusters_tenant_isolation ON finding_clusters
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE finding_clusters ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE finding_clusters FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- finding_severity_overrides
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='finding_severity_overrides') THEN
    EXECUTE 'CREATE POLICY finding_severity_overrides_tenant_isolation ON finding_severity_overrides
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE finding_severity_overrides ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE finding_severity_overrides FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- finding_suppression_rules
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='finding_suppression_rules') THEN
    EXECUTE 'CREATE POLICY finding_suppression_rules_tenant_isolation ON finding_suppression_rules
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE finding_suppression_rules ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE finding_suppression_rules FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- scope_decision_logs
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='scope_decision_logs') THEN
    EXECUTE 'CREATE POLICY scope_decision_logs_tenant_isolation ON scope_decision_logs
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE scope_decision_logs ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE scope_decision_logs FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

-- user_dashboard_layouts
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='user_dashboard_layouts') THEN
    EXECUTE 'CREATE POLICY user_dashboard_layouts_tenant_isolation ON user_dashboard_layouts
        FOR ALL TO PUBLIC
        USING (vaultscan_current_tenant_id() IS NULL
               OR tenant_id = vaultscan_current_tenant_id())';
    EXECUTE 'ALTER TABLE user_dashboard_layouts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE user_dashboard_layouts FORCE  ROW LEVEL SECURITY';
  END IF;
END $$;

COMMIT;
