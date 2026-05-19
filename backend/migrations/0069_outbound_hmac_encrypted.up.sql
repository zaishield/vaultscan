-- 0069_outbound_hmac_encrypted.up.sql
--
-- Move the outbound webhook HMAC secret out of the JSONB config
-- column and into a vault-wrapped BYTEA column. Mirrors the
-- signing_secret_encrypted pattern from migration 0056 (inbound).
--
-- Before this migration: integrations.config JSONB stored
-- `hmac_secret` as plaintext. Anyone with SELECT on the integrations
-- row (manage_integrations role, DB backup access, log scrapers
-- that captured a SELECT) saw the live signing secret.
--
-- After: a new column outbound_hmac_secret_encrypted holds the
-- AES-GCM-wrapped secret (master KEK envelope); outbound_hmac_key_version
-- records which KEK wrapped it; the JSONB config no longer carries
-- the key.
--
-- Code path:
--   Service.SetOutboundHMACSecret stores via wrapper.WrapBytes.
--   Service.outboundHMACSecret retrieves via wrapper.UnwrapBlob.
--   Test/Send paths call outboundHMACSecret; legacy config.hmac_secret
--   is a fallback for tenants not yet migrated.

ALTER TABLE integrations
    ADD COLUMN IF NOT EXISTS outbound_hmac_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS outbound_hmac_key_version       INTEGER;

COMMENT ON COLUMN integrations.outbound_hmac_secret_encrypted IS
    'AES-GCM-wrapped outbound webhook signing secret. Replaces the plaintext hmac_secret in the JSONB config column (kept for back-compat during migration window).';
