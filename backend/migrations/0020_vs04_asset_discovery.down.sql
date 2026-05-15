-- Reverses 0020_vs04_asset_discovery.up.sql.
DROP INDEX IF EXISTS assets_dedup_key_idx;
DROP TRIGGER IF EXISTS assets_dedup_key_trigger ON assets;
DROP FUNCTION IF EXISTS vaultscan_asset_dedup_key();
ALTER TABLE assets DROP COLUMN IF EXISTS dedup_key;

DROP INDEX IF EXISTS asset_discovery_scanjob_idx;
ALTER TABLE asset_discovery_history DROP COLUMN IF EXISTS tool;
ALTER TABLE asset_discovery_history DROP COLUMN IF EXISTS scan_job_id;

DROP TABLE IF EXISTS asset_relationships CASCADE;
