-- Reverses 0027_vs11_integrations_ops.up.sql.
ALTER TABLE integrations DROP COLUMN IF EXISTS issue_type;
ALTER TABLE integrations DROP COLUMN IF EXISTS format;
DROP TABLE IF EXISTS integration_replays      CASCADE;
DROP TABLE IF EXISTS integration_dead_letters CASCADE;
