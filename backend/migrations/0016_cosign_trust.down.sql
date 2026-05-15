-- Reverses 0016_cosign_trust.up.sql.
DROP TABLE IF EXISTS cosign_verifications  CASCADE;
DROP TABLE IF EXISTS cosign_trusted_keys    CASCADE;
ALTER TABLE scanner_image_registry DROP COLUMN IF EXISTS cosign_payload;
ALTER TABLE scanner_image_registry DROP COLUMN IF EXISTS cosign_key_id;
