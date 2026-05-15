-- 0041 — Storage table for the AWS KMS / Azure Key Vault / GCP KMS
-- secrets backends. Secrets stay encrypted at rest with the cloud
-- KMS-wrapped ciphertext; this table just holds opaque ciphertext
-- blobs keyed by ref.
--
-- Read path: SELECT ciphertext_b64 → KMS Decrypt → plaintext.
-- Write path: KMS Encrypt → INSERT.
--
-- The OpenBao + Infisical backends do NOT use this table; they fetch
-- straight from their respective HTTP APIs.

CREATE TABLE IF NOT EXISTS vaultscan_secrets (
    ref            TEXT PRIMARY KEY,
    ciphertext_b64 TEXT NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit who/when last touched each secret.
ALTER TABLE vaultscan_secrets
    ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS vaultscan_secrets_updated_idx
    ON vaultscan_secrets(updated_at DESC);
