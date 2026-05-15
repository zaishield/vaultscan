-- HS-01 deepening: real TOTP/MFA + RSA JWT signing with rotation + JWKS.
--
-- Before this migration:
--   - users.mfa_enabled was a bool the API never actually checked
--     against a real second factor.
--   - JWTs were signed with a single HS256 shared secret. Rotation
--     meant cutting all in-flight sessions.
--
-- After:
--   - user_mfa carries the AES-GCM-wrapped TOTP shared secret + the
--     8 backup recovery codes (hashed, single-use). enrolled_at +
--     last_verified_at give the admin UI a posture view.
--   - jwt_signing_keys holds RSA keypairs. Tokens are signed with the
--     single active row; verification accepts any row with
--     status='active' OR status='verify_only', so a key rotation
--     adds a new active row + marks the old one verify_only (no
--     mid-session breakage) and after the access-token lifespan
--     elapses the old key drops to status='retired'.

-- 1. Real MFA enrollment table -----------------------------------------------

CREATE TABLE user_mfa (
    user_id              UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_secret_encrypted BYTEA NOT NULL,            -- nonce || AES-256-GCM(plaintext)
    totp_secret_kek_id   TEXT NOT NULL,             -- which platform KEK wrapped it
    enrolled_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at     TIMESTAMPTZ,
    recovery_codes       JSONB NOT NULL DEFAULT '[]', -- array of bcrypt hashes
    recovery_codes_left  INTEGER NOT NULL DEFAULT 8
);

-- Ephemeral challenge so the second-step verify isn't trivially
-- replayable. Cleaned by the cron sweeper.
CREATE TABLE mfa_challenges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ
);
CREATE INDEX mfa_challenges_active_idx
    ON mfa_challenges(user_id, expires_at)
    WHERE consumed_at IS NULL;

-- 2. JWT signing key set -----------------------------------------------------

CREATE TABLE jwt_signing_keys (
    kid               TEXT PRIMARY KEY,                  -- exposed in token header
    alg               TEXT NOT NULL DEFAULT 'RS256',
    public_key_pem    TEXT NOT NULL,
    private_key_encrypted BYTEA NOT NULL,                -- AES-GCM under platform KEK
    private_key_kek_id    TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active',   -- active | verify_only | retired
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at        TIMESTAMPTZ
);
CREATE INDEX jwt_signing_keys_status_idx ON jwt_signing_keys(status);

-- Exactly one row may be 'active' at any time so the signer never has
-- to guess which one to use.
CREATE UNIQUE INDEX jwt_signing_keys_single_active
    ON jwt_signing_keys((1)) WHERE status = 'active';

-- 3. Tighten users column ----------------------------------------------------

-- Keep the boolean for backward compatibility but use mfa_status as
-- the authoritative state going forward.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_status TEXT NOT NULL DEFAULT 'none';
  -- none | enrolled | required (admin force-enrol)
CREATE INDEX users_mfa_status_idx ON users(mfa_status) WHERE mfa_status <> 'none';

-- Backfill: users with mfa_enabled=true become 'enrolled' (best-effort —
-- they'll re-enrol on next login since we don't have the TOTP secret).
UPDATE users SET mfa_status = 'enrolled' WHERE mfa_enabled = true;
