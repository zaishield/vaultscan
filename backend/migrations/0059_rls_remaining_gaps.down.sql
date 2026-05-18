-- 0059_rls_remaining_gaps.down.sql — reverses 0059 cleanly.

DROP POLICY IF EXISTS external_data_sources_tenant_isolation     ON external_data_sources;
ALTER TABLE external_data_sources NO FORCE ROW LEVEL SECURITY;
ALTER TABLE external_data_sources DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ct_log_entries_tenant_isolation            ON ct_log_entries;
ALTER TABLE ct_log_entries NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ct_log_entries DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS partner_customer_mapping_tenant_isolation  ON partner_customer_mapping;
ALTER TABLE partner_customer_mapping NO FORCE ROW LEVEL SECURITY;
ALTER TABLE partner_customer_mapping DISABLE ROW LEVEL SECURITY;
