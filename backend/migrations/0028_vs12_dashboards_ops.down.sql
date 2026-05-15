-- Reverses 0028_vs12_dashboards_ops.up.sql.
ALTER TABLE scanner_node_registry DROP COLUMN IF EXISTS country;
ALTER TABLE scanner_node_registry DROP COLUMN IF EXISTS city;
ALTER TABLE scanner_node_registry DROP COLUMN IF EXISTS longitude;
ALTER TABLE scanner_node_registry DROP COLUMN IF EXISTS latitude;
DROP TABLE IF EXISTS dashboard_sse_subscriptions CASCADE;
DROP INDEX IF EXISTS user_dashboard_layouts_default_unique;
DROP TABLE IF EXISTS user_dashboard_layouts CASCADE;
