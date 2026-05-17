-- 0054_dedicated_isolation.down.sql
DROP INDEX IF EXISTS tenant_isolation_history_tenant_idx;
DROP TABLE IF EXISTS tenant_isolation_history;
DROP INDEX IF EXISTS tenant_pool_routing_kind_idx;
DROP TABLE IF EXISTS tenant_pool_routing;
ALTER TABLE tenant_data_keys DROP COLUMN IF EXISTS dedicated_kek_ref;
