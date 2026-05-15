-- VS-11 Integrations & Event Bus / HS-02 Audit & Compliance
-- Blueprint §22, §31, §32

CREATE TABLE integrations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID REFERENCES tenants(id) ON DELETE CASCADE,
    partner_id    UUID REFERENCES partners(id) ON DELETE CASCADE,
    type          TEXT NOT NULL,    -- jira | servicenow | slack | teams | webhook | siem | gitlab | github | jenkins
    name          TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    config        JSONB NOT NULL DEFAULT '{}',
    secret_ref    TEXT,                            -- pointer into OpenBao/Infisical, never plaintext
    event_filter  JSONB NOT NULL DEFAULT '[]',     -- list of event types to forward
    last_status   TEXT,
    last_check_at TIMESTAMPTZ,
    created_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX integrations_tenant_idx ON integrations(tenant_id);
CREATE INDEX integrations_partner_idx ON integrations(partner_id);
CREATE INDEX integrations_type_idx ON integrations(type);

CREATE TABLE integration_deliveries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    event_id      UUID NOT NULL,
    event_type    TEXT NOT NULL,
    attempt       INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | delivered | failed | retrying
    response_code INTEGER,
    response_body TEXT,
    next_retry_at TIMESTAMPTZ,
    delivered_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX integration_deliveries_integration_idx ON integration_deliveries(integration_id, status);

CREATE TABLE bus_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type    TEXT NOT NULL,
    tenant_id     UUID REFERENCES tenants(id) ON DELETE CASCADE,
    partner_id    UUID REFERENCES partners(id) ON DELETE CASCADE,
    actor_id      UUID REFERENCES users(id),
    payload       JSONB NOT NULL DEFAULT '{}',
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX bus_events_type_idx     ON bus_events(event_type, occurred_at DESC);
CREATE INDEX bus_events_tenant_idx   ON bus_events(tenant_id, occurred_at DESC);

-- Audit / Compliance (Blueprint §32)
CREATE TABLE audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    platform_id   UUID NOT NULL REFERENCES platforms(id),
    partner_id    UUID REFERENCES partners(id),
    tenant_id     UUID REFERENCES tenants(id),
    actor_id      UUID REFERENCES users(id),
    actor_type    TEXT NOT NULL DEFAULT 'user',     -- user | service | agent | system
    event         TEXT NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    payload       JSONB NOT NULL DEFAULT '{}',
    ip            INET,
    user_agent    TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    chain_prev    BYTEA,                            -- prior log row hash
    chain_hash    BYTEA NOT NULL                    -- sha256(prev || row)
);
CREATE INDEX audit_logs_event_idx     ON audit_logs(event, occurred_at DESC);
CREATE INDEX audit_logs_tenant_idx    ON audit_logs(tenant_id, occurred_at DESC);
CREATE INDEX audit_logs_actor_idx     ON audit_logs(actor_id, occurred_at DESC);

-- Append-only enforcement
REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;

CREATE TABLE security_events (
    id            BIGSERIAL PRIMARY KEY,
    event         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    payload       JSONB NOT NULL DEFAULT '{}',
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_actions (
    id            BIGSERIAL PRIMARY KEY,
    actor_id      UUID REFERENCES users(id),
    action        TEXT NOT NULL,
    target        TEXT,
    payload       JSONB NOT NULL DEFAULT '{}',
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE login_events (
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID REFERENCES users(id),
    email         CITEXT,
    success       BOOLEAN NOT NULL,
    ip            INET,
    user_agent    TEXT,
    mfa_used      BOOLEAN,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
