-- Reverses 0035_enrichment_and_notify.up.sql.
DROP INDEX IF EXISTS notification_queue_due_idx;
DROP TABLE IF EXISTS notification_queue CASCADE;
DROP TABLE IF EXISTS notification_channels CASCADE;

DROP INDEX IF EXISTS cloud_drift_recent_idx;
DROP TABLE IF EXISTS cloud_drift_events CASCADE;
DROP INDEX IF EXISTS cloud_posture_snapshots_recent_idx;
DROP TABLE IF EXISTS cloud_posture_snapshots CASCADE;
DROP TABLE IF EXISTS cloud_accounts CASCADE;

DROP TABLE IF EXISTS vuln_data_sources    CASCADE;
DROP TABLE IF EXISTS vendor_advisories     CASCADE;
DROP INDEX IF EXISTS cve_metadata_epss_idx;
DROP INDEX IF EXISTS cve_metadata_kev_idx;
DROP TABLE IF EXISTS cve_metadata          CASCADE;

DROP INDEX IF EXISTS ct_log_entries_tenant_idx;
DROP INDEX IF EXISTS ct_log_entries_dedup_idx;
DROP TABLE IF EXISTS ct_log_entries        CASCADE;
DROP INDEX IF EXISTS asset_enrichments_asset_idx;
DROP TABLE IF EXISTS asset_enrichments     CASCADE;
DROP INDEX IF EXISTS external_data_sources_due_idx;
DROP TABLE IF EXISTS external_data_sources CASCADE;
