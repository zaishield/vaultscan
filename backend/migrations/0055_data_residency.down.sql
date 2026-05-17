-- 0055_data_residency.down.sql
DROP TABLE IF EXISTS tenant_residency_history;
ALTER TABLE tenants DROP COLUMN IF EXISTS data_region;
