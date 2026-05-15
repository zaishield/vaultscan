-- Reverses 0019_vs03_engagements.up.sql.
DROP TABLE IF EXISTS authorization_access_logs CASCADE;
ALTER TABLE engagements DROP COLUMN IF EXISTS max_scans_per_hour;
ALTER TABLE engagements DROP COLUMN IF EXISTS paused_at;
ALTER TABLE engagements DROP COLUMN IF EXISTS pause_reason;
