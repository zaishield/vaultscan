-- 0056_inbound_webhook_secrets.up.sql
--
-- Per-integration signing secret for inbound webhook verification.
-- internal/integrations/inbound.go ships the HMAC-SHA256 verifier;
-- this column gives it a place to look up the secret per integration.
--
-- The secret is treated like any other credential: encrypted at rest
-- under the evidence DEK. The application layer wraps the column read
-- with the same Vault.Unwrap path used for integration credentials.
-- We store the encrypted blob (BYTEA) — never plaintext.
--
-- Convention: NULL = no inbound signature enforcement for this
-- integration. The handler refuses inbound callbacks for any
-- integration whose signing_secret IS NULL when the verification
-- gate is required by config (VAULTSCAN_REQUIRE_INBOUND_SIG=true,
-- default in production).

ALTER TABLE integrations
    ADD COLUMN IF NOT EXISTS signing_secret_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS signing_key_version INTEGER,
    ADD COLUMN IF NOT EXISTS signing_algorithm TEXT NOT NULL DEFAULT 'hmac-sha256';

COMMENT ON COLUMN integrations.signing_secret_encrypted IS
    'KEK/DEK-sealed shared secret used to verify inbound webhook HMAC-SHA256 signatures. NULL = inbound verification disabled.';

-- Inbound-delivery audit trail. Logs every inbound webhook
-- regardless of verification outcome so an operator can prove
-- "we received but rejected this event at 12:03 UTC".
CREATE TABLE IF NOT EXISTS integration_inbound_log (
    id              BIGSERIAL PRIMARY KEY,
    integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified        BOOLEAN NOT NULL,
    rejection_code  TEXT,        -- "missing_signature" | "skew" | "mismatch" | "no_secret" | NULL
    source_ip       INET,
    body_sha256     TEXT,        -- hex of payload digest; lets ops correlate without storing payload
    headers_subset  JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS integration_inbound_log_integration_idx
    ON integration_inbound_log(integration_id, received_at DESC);
CREATE INDEX IF NOT EXISTS integration_inbound_log_rejected_idx
    ON integration_inbound_log(rejection_code, received_at DESC)
 WHERE verified = false;
