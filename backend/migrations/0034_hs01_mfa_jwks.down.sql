-- Reverses 0034_hs01_mfa_jwks.up.sql.
DROP INDEX IF EXISTS users_mfa_status_idx;
ALTER TABLE users DROP COLUMN IF EXISTS mfa_status;

DROP INDEX IF EXISTS jwt_signing_keys_single_active;
DROP INDEX IF EXISTS jwt_signing_keys_status_idx;
DROP TABLE IF EXISTS jwt_signing_keys CASCADE;

DROP INDEX IF EXISTS mfa_challenges_active_idx;
DROP TABLE IF EXISTS mfa_challenges CASCADE;
DROP TABLE IF EXISTS user_mfa CASCADE;
