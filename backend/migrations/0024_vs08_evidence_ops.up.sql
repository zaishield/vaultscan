-- VS-08 deepening: envelope encryption (per-tenant DEK wrapped by platform
-- KEK), chain-of-custody log, WORM mode.
--
-- Today every evidence object is sealed with the platform master key.
-- Envelope encryption replaces that with two keys: the platform KEK
-- (configured at boot) wraps a per-tenant DEK; the DEK seals the actual
-- bytes. Compromise of any one tenant's DEK doesn't leak others, and a
-- KEK rotation only needs to re-wrap the small DEK rows — not rewrite
-- every object.

CREATE TABLE tenant_data_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_version     INTEGER NOT NULL,
    wrapped_key     BYTEA NOT NULL,             -- KEK-encrypted DEK (nonce || GCM ct)
    kek_id          TEXT NOT NULL,              -- "platform-master-v1"
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at      TIMESTAMPTZ,
    UNIQUE (tenant_id, key_version)
);
CREATE INDEX tenant_data_keys_lookup_idx
    ON tenant_data_keys(tenant_id, key_version);

-- Which DEK version sealed this object. Old objects (pre-VS-08) keep
-- version NULL — the read path falls back to the legacy master-key path.
ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS encryption_key_version INTEGER;

-- WORM (write-once-read-many). When true, the retention sweeper refuses
-- to purge the object even past expires_at, and unauthorised delete
-- attempts are logged in evidence_chain_of_custody.
ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS worm BOOLEAN NOT NULL DEFAULT false;

-- Chain of custody: ordered events per evidence object so the legal
-- export bundle can answer "who touched this file when?". Differs from
-- evidence_access_logs in that it's append-only forever and includes
-- system events (integrity_verified, worm_locked, purge_attempted).
CREATE TABLE evidence_chain_of_custody (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id     UUID NOT NULL REFERENCES finding_evidence(id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    actor_id        UUID REFERENCES users(id),
    actor_type      TEXT NOT NULL DEFAULT 'user',
    ip              INET,
    user_agent      TEXT,
    details         JSONB NOT NULL DEFAULT '{}',
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_chain_evidence_idx
    ON evidence_chain_of_custody(evidence_id, occurred_at);
