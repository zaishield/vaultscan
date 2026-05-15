-- 0040 down — remove the RLS policies and disable RLS on the tables we
-- enabled in this migration. Idempotent: missing tables/policies are
-- silently skipped.

BEGIN;

DO $$
DECLARE
  tables TEXT[] := ARRAY[
    'engagements','scan_jobs','agents','integrations','reports',
    'report_schedules','tenant_branding','tenant_settings',
    'tenant_data_keys','clients','cloud_accounts','notification_channels',
    'retest_batches','marketplace_installs','customer_feedback',
    'finding_clusters','finding_severity_overrides','finding_suppression_rules',
    'scope_decision_logs','user_dashboard_layouts'
  ];
  tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY tables LOOP
    BEGIN
      EXECUTE format('DROP POLICY IF EXISTS %I_tenant_isolation ON %I', tbl, tbl);
      EXECUTE format('ALTER TABLE IF EXISTS %I DISABLE ROW LEVEL SECURITY', tbl);
      EXECUTE format('ALTER TABLE IF EXISTS %I NO FORCE ROW LEVEL SECURITY', tbl);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
END $$;

COMMIT;
