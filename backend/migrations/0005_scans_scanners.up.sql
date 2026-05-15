-- VS-05 External Scanner Plane / VS-06 Internal Agent Plane (job tables)
-- Blueprint §5, §11, §12, §20.1

CREATE TABLE scan_profiles (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code          TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    plane         TEXT NOT NULL,      -- external | internal
    intensity     TEXT NOT NULL DEFAULT 'standard',
    description   TEXT,
    tools         JSONB NOT NULL DEFAULT '[]',
    parameters    JSONB NOT NULL DEFAULT '{}',
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO scan_profiles(code, name, plane, intensity, description, tools, requires_approval) VALUES
    ('external_discovery',     'External Discovery',     'external', 'light',
        'Subdomain & port discovery with passive enumeration',
        '["amass","subfinder","dnsx","httpx","naabu","nmap"]'::jsonb, false),
    ('external_standard_va',   'External Standard VA',   'external', 'standard',
        'Network + service vulnerability scan',
        '["nmap","openvas","nuclei"]'::jsonb, false),
    ('external_web_va',        'External Web VA',        'external', 'standard',
        'Web/API DAST with template-based detection',
        '["zap","nuclei","katana","ffuf"]'::jsonb, false),
    ('external_tls_review',    'External TLS Review',    'external', 'light',
        'SSL/TLS posture review',
        '["testssl","sslyze","httpx"]'::jsonb, false),
    ('external_aggressive_va', 'External Aggressive VA', 'external', 'aggressive',
        'Intrusive checks (requires approval)',
        '["zap","nuclei","openvas","nmap"]'::jsonb, true),
    ('internal_discovery',     'Internal Discovery',     'internal', 'light',
        'Internal port/service discovery',
        '["nmap","naabu"]'::jsonb, false),
    ('internal_standard_va',   'Internal Standard VA',   'internal', 'standard',
        'Internal vulnerability scan',
        '["openvas","nuclei","nmap"]'::jsonb, false),
    ('internal_web_va',        'Internal Web VA',        'internal', 'standard',
        'Internal web app DAST',
        '["zap","nuclei"]'::jsonb, false),
    ('internal_ad_review',     'Internal AD Review',     'internal', 'standard',
        'Active Directory enumeration & relationship mapping',
        '["bloodhound","netexec","nmap"]'::jsonb, false),
    ('internal_linux_hardening','Internal Linux Hardening','internal','light',
        'Linux/Unix hardening review',
        '["lynis"]'::jsonb, false),
    ('internal_k8s_review',    'Internal Kubernetes Review','internal','standard',
        'Kubernetes posture review',
        '["kube-bench","kube-hunter","trivy"]'::jsonb, false),
    ('internal_container_review','Internal Container Review','internal','standard',
        'Container image / runtime review',
        '["trivy","grype","syft"]'::jsonb, false),
    ('cloud_posture',          'Cloud Posture Review',   'external', 'standard',
        'Cloud security posture',
        '["prowler","scoutsuite"]'::jsonb, false),
    ('mobile_static',          'Mobile Static Review',   'external', 'standard',
        'Android/iOS APK/IPA static analysis',
        '["mobsf"]'::jsonb, false);

CREATE TABLE scanner_node_registry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region          TEXT NOT NULL,             -- ae | eu | in | us | sg | sa | uk
    hostname        TEXT NOT NULL,
    public_ip       INET NOT NULL,
    capacity_jobs   INTEGER NOT NULL DEFAULT 4,
    cpu_cores       INTEGER NOT NULL,
    memory_mb       INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'online',
    last_heartbeat  TIMESTAMPTZ,
    abuse_contact   TEXT,
    reverse_dns     TEXT,
    UNIQUE (region, hostname)
);

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id),
    partner_id      UUID NOT NULL REFERENCES partners(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id)   ON DELETE CASCADE,
    engagement_id   UUID NOT NULL REFERENCES engagements(id),
    profile_id      UUID NOT NULL REFERENCES scan_profiles(id),
    plane           TEXT NOT NULL,                    -- external | internal
    region          TEXT,                             -- external scanner region
    agent_id        UUID,                             -- internal agent (FK in 0006)
    scanner_node_id UUID REFERENCES scanner_node_registry(id),
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | dispatched | running | succeeded | failed | cancelled | stopped
    target_summary  TEXT NOT NULL,
    targets         JSONB NOT NULL DEFAULT '[]',
    schedule_at     TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    approved_by     UUID REFERENCES users(id),
    approved_at     TIMESTAMPTZ,
    job_signature   TEXT,                             -- HMAC/RSA signature
    signing_key_id  TEXT,
    requested_by    UUID REFERENCES users(id),
    cancellation_reason TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scan_jobs_tenant_idx     ON scan_jobs(tenant_id);
CREATE INDEX scan_jobs_engagement_idx ON scan_jobs(engagement_id);
CREATE INDEX scan_jobs_status_idx     ON scan_jobs(status);
CREATE INDEX scan_jobs_agent_idx      ON scan_jobs(agent_id);

CREATE TABLE scan_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id     UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    tool            TEXT NOT NULL,
    image_ref       TEXT NOT NULL,
    image_digest    TEXT,
    status          TEXT NOT NULL DEFAULT 'queued',  -- queued | running | succeeded | failed | killed
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    exit_code       INTEGER,
    cpu_limit       TEXT,
    memory_limit    TEXT,
    runtime_limit_s INTEGER,
    output_summary  JSONB
);
CREATE INDEX scan_tasks_job_idx ON scan_tasks(scan_job_id);

CREATE TABLE scanner_outputs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_task_id UUID NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    storage_url  TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    content_type TEXT NOT NULL,
    encrypted    BOOLEAN NOT NULL DEFAULT true,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scan_approval_logs
    ADD CONSTRAINT scan_approval_logs_job_fk
    FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE SET NULL;
