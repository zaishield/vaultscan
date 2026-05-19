-- 0069_outbound_hmac_encrypted.down.sql
ALTER TABLE integrations
    DROP COLUMN IF EXISTS outbound_hmac_secret_encrypted,
    DROP COLUMN IF EXISTS outbound_hmac_key_version;
