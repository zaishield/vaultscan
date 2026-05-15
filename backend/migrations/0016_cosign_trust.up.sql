-- Cosign trust policy. Each trusted key gets one row; the scanner worker
-- and admission controller reject any image whose signature doesn't verify
-- against at least one ENABLED row whose plane covers the request.
--
-- Operators rotate keys by:
--   1. Insert the new row (enabled=true).
--   2. Re-sign and re-push every active image with the new key.
--   3. Disable the old row (enabled=false).
-- Once disabled, the chain still verifies historic signatures (audit
-- trail), but new images cannot be signed-and-trusted by the old key.

CREATE TABLE cosign_trusted_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id          TEXT NOT NULL UNIQUE,    -- e.g. "zaishield-prod-2026-q1"
    algorithm       TEXT NOT NULL,           -- ecdsa-p256-sha256 | rsa-pss-sha256
    public_key_pem  TEXT NOT NULL,
    plane           TEXT NOT NULL DEFAULT 'both',  -- external | internal | both
    subject         TEXT,                    -- optional: OIDC subject (Fulcio keyless mode)
    issuer          TEXT,                    -- optional: OIDC issuer for keyless mode
    enabled         BOOLEAN NOT NULL DEFAULT true,
    registered_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX cosign_keys_active_idx
    ON cosign_trusted_keys(enabled, plane)
    WHERE enabled = true AND revoked_at IS NULL;

-- Per-image signature payloads we accept. Production stores these as OCI
-- artifacts in the registry; this table is the trust-cache so the scanner
-- worker doesn't need outbound network access to the registry at run time.
ALTER TABLE scanner_image_registry ADD COLUMN IF NOT EXISTS cosign_payload TEXT;
ALTER TABLE scanner_image_registry ADD COLUMN IF NOT EXISTS cosign_signature TEXT;
ALTER TABLE scanner_image_registry ADD COLUMN IF NOT EXISTS cosign_key_id TEXT;
ALTER TABLE scanner_image_registry ADD COLUMN IF NOT EXISTS cosign_verified_at TIMESTAMPTZ;

-- Verification audit: every accept / reject decision lands here so an
-- auditor can prove which signatures we trusted, when, and why.
CREATE TABLE cosign_verifications (
    id            BIGSERIAL PRIMARY KEY,
    image_ref     TEXT NOT NULL,
    image_digest  TEXT NOT NULL,
    key_id        TEXT,
    decision      TEXT NOT NULL,   -- accepted | rejected_unknown_key | rejected_signature | rejected_disabled | rejected_subject
    reason        TEXT,
    actor_id      UUID,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cosign_verifications_image_idx ON cosign_verifications(image_ref, occurred_at DESC);
