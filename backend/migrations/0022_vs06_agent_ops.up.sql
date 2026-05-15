-- VS-06 deepening: real cert rotation, durable telemetry, signed update
-- bundles, and emergency-stop SLA tracking.

-- Agent submits a CSR (PKCS#10 PEM). Cloud-side CA mints the cert and
-- writes the row. The agent then polls for the resulting pem.
CREATE TABLE agent_csr_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    csr_pem         TEXT NOT NULL,
    csr_sha256      TEXT NOT NULL,                  -- helps the agent re-check it's looking at its own CSR
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | issued | rejected | expired
    rejection_reason TEXT,
    issued_cert_id  UUID REFERENCES agent_certificates(id),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ
);
CREATE INDEX agent_csr_pending_idx
    ON agent_csr_requests(agent_id, status)
    WHERE status = 'pending';

-- Telemetry rollup: rolling 5-minute aggregate of heartbeat metrics so a
-- year of agent stats stays queryable without exploding the heartbeats
-- table. Worker fills this hourly from agent_heartbeats.
CREATE TABLE agent_telemetry_rollups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    bucket_start    TIMESTAMPTZ NOT NULL,
    bucket_minutes  INTEGER NOT NULL DEFAULT 5,
    samples         INTEGER NOT NULL,
    cpu_avg         NUMERIC(5,2) NOT NULL,
    cpu_peak        NUMERIC(5,2) NOT NULL,
    memory_avg      NUMERIC(5,2) NOT NULL,
    memory_peak     NUMERIC(5,2) NOT NULL,
    disk_avg        NUMERIC(5,2),
    queue_peak      INTEGER NOT NULL DEFAULT 0,
    UNIQUE (agent_id, bucket_start, bucket_minutes)
);
CREATE INDEX agent_telemetry_lookup_idx
    ON agent_telemetry_rollups(agent_id, bucket_start DESC);

-- Signed agent update bundles. Each entry advertises a target_version,
-- a download_url, the sha256 of the bundle bytes, the bundle's signature
-- (cloud-CA private key signs the manifest), and the signing key id.
-- Agents refuse to install a bundle whose signature doesn't verify
-- against any active key in cosign_trusted_keys.
CREATE TABLE agent_update_bundles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_version  TEXT NOT NULL UNIQUE,
    download_url    TEXT NOT NULL,
    bundle_sha256   TEXT NOT NULL,
    manifest_json   JSONB NOT NULL,           -- canonical form the signature covers
    manifest_signature TEXT NOT NULL,         -- base64 RSA-PSS over manifest_json bytes
    signing_key_id  TEXT NOT NULL,
    min_from_version TEXT,                     -- if set, agents below this can't jump straight to this
    rollout_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rollout_paused  BOOLEAN NOT NULL DEFAULT false,
    notes           TEXT
);

CREATE TABLE agent_update_assignments (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    bundle_id        UUID NOT NULL REFERENCES agent_update_bundles(id) ON DELETE CASCADE,
    offered_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    fetched_at       TIMESTAMPTZ,
    installed_at     TIMESTAMPTZ,
    install_success  BOOLEAN,
    install_error    TEXT,
    UNIQUE (agent_id, bundle_id)
);

-- Emergency-stop SLA tracking. arrival_ts = cloud accepted operator
-- request; ack_ts = agent's heartbeat acknowledged the stop. The
-- difference is what we hold our 30-second SLA against (Blueprint §28.2).
CREATE TABLE agent_emergency_stops (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL,
    requested_by UUID REFERENCES users(id),
    arrival_ts   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ack_ts       TIMESTAMPTZ,
    resolved_ts  TIMESTAMPTZ,
    sla_ms       INTEGER,                    -- arrival → ack in milliseconds
    scope        TEXT NOT NULL DEFAULT 'agent', -- agent | tenant | engagement
    metadata     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX agent_emergency_stops_agent_idx
    ON agent_emergency_stops(agent_id, arrival_ts DESC);
