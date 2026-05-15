-- VS-03 Engagement & Scope Guard
-- Blueprint §14, §20.1

CREATE TABLE clients (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    industry     TEXT,
    contact_name TEXT,
    contact_email TEXT,
    contact_phone TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX clients_tenant_idx ON clients(tenant_id);

CREATE TABLE engagements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id),
    partner_id      UUID NOT NULL REFERENCES partners(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       UUID REFERENCES clients(id) ON DELETE SET NULL,
    code            TEXT NOT NULL,           -- e.g. ENG-2026-0001
    name            TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'draft',  -- draft | active | paused | expired | closed
    starts_at       TIMESTAMPTZ NOT NULL,
    ends_at         TIMESTAMPTZ NOT NULL,
    intensity       TEXT NOT NULL DEFAULT 'standard',  -- light | standard | aggressive
    emergency_contact_name  TEXT,
    emergency_contact_email TEXT,
    emergency_contact_phone TEXT,
    created_by      UUID REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, code)
);
CREATE INDEX engagements_tenant_idx ON engagements(tenant_id);
CREATE INDEX engagements_status_idx ON engagements(status);

CREATE TABLE authorization_documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    document_type   TEXT NOT NULL,        -- letter | roe | nda | insurance
    storage_url     TEXT NOT NULL,        -- s3://...
    sha256          TEXT NOT NULL,
    signed_by       TEXT,
    signed_at       TIMESTAMPTZ,
    uploaded_by     UUID REFERENCES users(id),
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    encrypted       BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX authdocs_engagement_idx ON authorization_documents(engagement_id);

CREATE TABLE rules_of_engagement (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    allowed_techniques  JSONB NOT NULL DEFAULT '[]',
    restricted_techniques JSONB NOT NULL DEFAULT '[]',
    scan_window_start TIME,
    scan_window_end   TIME,
    days_of_week      JSONB NOT NULL DEFAULT '["mon","tue","wed","thu","fri"]',
    max_intensity     TEXT NOT NULL DEFAULT 'standard',
    notify_emails     JSONB NOT NULL DEFAULT '[]',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scope_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    target_type     TEXT NOT NULL,    -- domain | subdomain | ip | cidr | url | api | k8s | mobile_app | repo
    target_value    TEXT NOT NULL,
    plane           TEXT NOT NULL,    -- external | internal
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
    approved_by     UUID REFERENCES users(id),
    approved_at     TIMESTAMPTZ,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scope_engagement_idx ON scope_targets(engagement_id);
CREATE UNIQUE INDEX scope_unique_idx ON scope_targets(engagement_id, target_type, target_value);

CREATE TABLE scope_decision_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE SET NULL,
    tenant_id     UUID REFERENCES tenants(id)     ON DELETE SET NULL,
    requested_by  UUID REFERENCES users(id),
    target_value  TEXT NOT NULL,
    target_type   TEXT NOT NULL,
    plane         TEXT NOT NULL,
    decision      TEXT NOT NULL,    -- approved | blocked_out_of_scope | blocked_missing_authorization | ...
    reason        TEXT,
    inputs        JSONB NOT NULL DEFAULT '{}',
    decided_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scope_decision_engagement_idx ON scope_decision_logs(engagement_id);
CREATE INDEX scope_decision_decided_at_idx ON scope_decision_logs(decided_at DESC);

CREATE TABLE scan_approval_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id   UUID,                 -- soft FK to scan_jobs (created in 0005)
    approved_by   UUID REFERENCES users(id),
    decision      TEXT NOT NULL,        -- approved | denied
    notes         TEXT,
    decided_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
