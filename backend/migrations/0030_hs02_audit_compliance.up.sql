-- HS-02 deepening: chain forensics, retention policy, SIEM streaming
-- checkpoint.

-- Retention policy per event type. Compliance regimes require different
-- holds: auth events (HIPAA = 6 years), scan events (PCI = 1 year),
-- finding events (forever). The retention worker references this table.
CREATE TABLE audit_retention_policies (
    event_prefix    TEXT PRIMARY KEY,        -- 'auth.*' | 'scan.*' | '*' (default)
    retention_days  INTEGER NOT NULL,
    archive_target  TEXT,                    -- 's3://...' or 'cold-pg'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO audit_retention_policies(event_prefix, retention_days, archive_target) VALUES
  ('*',          365 * 7, 's3://vaultscan-archive/audit/'),
  ('auth.',      365 * 6, 's3://vaultscan-archive/audit/auth/'),
  ('scan.',      365 * 3, 's3://vaultscan-archive/audit/scan/'),
  ('finding.',   365 * 10, 's3://vaultscan-archive/audit/finding/');

-- SIEM streaming checkpoint. The forwarder picks up where it left off
-- after a restart, so events aren't double-shipped or missed.
CREATE TABLE audit_siem_cursors (
    integration_id  UUID PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE,
    last_audit_id   BIGINT NOT NULL DEFAULT 0,
    last_shipped_at TIMESTAMPTZ,
    behind_count    INTEGER NOT NULL DEFAULT 0
);

-- Chain repair audit. The Verify pass logs every detected break here so
-- an auditor can reconstruct exactly when integrity diverged.
CREATE TABLE audit_chain_breaks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_bad_id    BIGINT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_good_id    BIGINT,
    detail          TEXT
);
