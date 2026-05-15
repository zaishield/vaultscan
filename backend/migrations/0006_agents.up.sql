-- VS-06 Internal Agent Plane
-- Blueprint §13, §20.3, §28

CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id),
    partner_id      UUID NOT NULL REFERENCES partners(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    location        TEXT,
    form_factor     TEXT NOT NULL DEFAULT 'linux_vm',  -- linux_vm | docker | k8s | hardware | windows_service
    version         TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | online | offline | quarantined | revoked
    last_heartbeat  TIMESTAMPTZ,
    cpu_percent     NUMERIC(5,2),
    memory_percent  NUMERIC(5,2),
    cert_status     TEXT NOT NULL DEFAULT 'none',      -- none | issued | expiring | revoked
    cert_expires_at TIMESTAMPTZ,
    emergency_stop_armed BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX agents_tenant_idx ON agents(tenant_id);
CREATE INDEX agents_status_idx ON agents(status);

ALTER TABLE scan_jobs
    ADD CONSTRAINT scan_jobs_agent_fk
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL;

CREATE TABLE agent_enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    issued_by   UUID REFERENCES users(id),
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX enroll_token_agent_idx ON agent_enrollment_tokens(agent_id);

CREATE TABLE agent_certificates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    serial        TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    pem           TEXT NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX agent_cert_agent_idx ON agent_certificates(agent_id);

CREATE TABLE agent_heartbeats (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_percent     NUMERIC(5,2),
    memory_percent  NUMERIC(5,2),
    disk_percent    NUMERIC(5,2),
    running_jobs    INTEGER NOT NULL DEFAULT 0,
    queue_depth     INTEGER NOT NULL DEFAULT 0,
    version         TEXT,
    payload         JSONB
);
CREATE INDEX heartbeats_agent_idx ON agent_heartbeats(agent_id, received_at DESC);

CREATE TABLE agent_policies (
    agent_id            UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    allowed_scopes      JSONB NOT NULL DEFAULT '[]',
    blocked_scopes      JSONB NOT NULL DEFAULT '[]',
    allowed_scan_profiles JSONB NOT NULL DEFAULT '[]',
    allowed_tools       JSONB NOT NULL DEFAULT '[]',
    max_concurrent_jobs INTEGER NOT NULL DEFAULT 2,
    max_cpu_percent     INTEGER NOT NULL DEFAULT 70,
    max_memory_percent  INTEGER NOT NULL DEFAULT 75,
    scan_window_start   TIME,
    scan_window_end     TIME,
    days_of_week        JSONB NOT NULL DEFAULT '["mon","tue","wed","thu","fri","sat","sun"]',
    emergency_stop_enabled BOOLEAN NOT NULL DEFAULT true,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_tool_inventory (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tool          TEXT NOT NULL,
    version       TEXT NOT NULL,
    image_digest  TEXT,
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, tool)
);

CREATE TABLE agent_assigned_scope (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    UNIQUE (agent_id, engagement_id)
);

CREATE TABLE agent_job_queue (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    scan_job_id   UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    state         TEXT NOT NULL DEFAULT 'queued',  -- queued | dispatched | acknowledged | done | failed
    enqueued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ
);
CREATE INDEX agent_queue_agent_idx ON agent_job_queue(agent_id, state);

CREATE TABLE agent_update_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    from_version  TEXT,
    to_version    TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    initiated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ,
    success       BOOLEAN
);

CREATE TABLE agent_audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_audit_agent_idx ON agent_audit_logs(agent_id, occurred_at DESC);
