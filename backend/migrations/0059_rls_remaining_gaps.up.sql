-- 0059_rls_remaining_gaps.up.sql
--
-- Closes the remaining tenant-scoped tables that the second audit
-- pass surfaced. Migration 0057 closed compliance_evidence +
-- dashboard_sse_subscriptions + idempotency_keys. This migration
-- adds RLS to:
--
--   partner_customer_mapping   — partner ↔ tenant lookup; without
--                                RLS a SQL injection could enumerate
--                                which tenants belong to other
--                                partners
--   ct_log_entries             — Certificate Transparency entries
--                                discovered by enrichment; per-tenant
--                                so an attacker shouldn't see another
--                                tenant's exposed cert inventory
--   external_data_sources      — per-tenant TI feed config (TAXII /
--                                ISAC / etc.); contains credentials
--                                + endpoints that should not leak
--
-- Tables explicitly LEFT WITHOUT RLS (audit pass confirmed each is
-- intentional, NOT a gap):
--
--   audit_logs                 — needs cross-tenant readability for
--                                audit.VerifyDeep + SIEM shipping
--   bus_events                 — internal event bus; cleaned up
--                                hourly; not user-readable
--   users                      — platform-scoped (a user can belong
--                                to multiple tenants via roles)
--   token_revocations          — per-user-id only (no tenant_id col)
--   on_call_shifts             — already RLS-enabled (0043)
--   platform_policy_rules      — platform-wide policy, no tenant_id
--   asset_enrichments          — global dedup by common-name lower;
--                                no tenant_id
--   asset_relationships        — scoped via asset_id FK (transitive
--                                from assets RLS)

ALTER TABLE partner_customer_mapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE partner_customer_mapping FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_customer_mapping_tenant_isolation
  ON partner_customer_mapping
  USING (
    tenant_id::text = current_setting('vaultscan.tenant_id', true)
    OR current_setting('vaultscan.tenant_id', true) = ''
    OR current_setting('vaultscan.tenant_id', true) IS NULL
  );

ALTER TABLE ct_log_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ct_log_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY ct_log_entries_tenant_isolation
  ON ct_log_entries
  USING (
    tenant_id::text = current_setting('vaultscan.tenant_id', true)
    OR current_setting('vaultscan.tenant_id', true) = ''
    OR current_setting('vaultscan.tenant_id', true) IS NULL
  );

ALTER TABLE external_data_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_data_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY external_data_sources_tenant_isolation
  ON external_data_sources
  USING (
    tenant_id::text = current_setting('vaultscan.tenant_id', true)
    OR current_setting('vaultscan.tenant_id', true) = ''
    OR current_setting('vaultscan.tenant_id', true) IS NULL
  );
