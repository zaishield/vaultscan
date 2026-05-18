-- 0056_inbound_webhook_secrets.down.sql
DROP TABLE IF EXISTS integration_inbound_log;
ALTER TABLE integrations
    DROP COLUMN IF EXISTS signing_secret_encrypted,
    DROP COLUMN IF EXISTS signing_key_version,
    DROP COLUMN IF EXISTS signing_algorithm;
