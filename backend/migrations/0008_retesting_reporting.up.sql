-- VS-09 Retesting / VS-10 Reporting
-- Blueprint §17.3, §19, §20.4

CREATE TABLE retest_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id    UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    requested_by  UUID REFERENCES users(id),
    note          TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | assigned | in_progress | passed | failed | cancelled
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at    TIMESTAMPTZ
);
CREATE INDEX retest_requests_finding_idx ON retest_requests(finding_id);

CREATE TABLE retest_assignments (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    retest_request_id UUID NOT NULL REFERENCES retest_requests(id) ON DELETE CASCADE,
    assignee_id       UUID NOT NULL REFERENCES users(id),
    assigned_by       UUID REFERENCES users(id),
    assigned_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE retest_results (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    retest_request_id UUID NOT NULL REFERENCES retest_requests(id) ON DELETE CASCADE,
    scan_job_id       UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    outcome           TEXT NOT NULL,  -- passed | failed
    summary           TEXT,
    decided_by        UUID REFERENCES users(id),
    decided_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE retest_evidence (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    retest_result_id  UUID NOT NULL REFERENCES retest_results(id) ON DELETE CASCADE,
    evidence_id       UUID NOT NULL REFERENCES finding_evidence(id) ON DELETE CASCADE
);

-- Reporting tables
CREATE TABLE report_templates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id   UUID REFERENCES partners(id) ON DELETE CASCADE,  -- null => platform default
    code         TEXT NOT NULL,
    name         TEXT NOT NULL,
    report_type  TEXT NOT NULL,
    sections     JSONB NOT NULL DEFAULT '[]',
    template_html TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- UNIQUE constraints don't accept expressions; use a UNIQUE INDEX instead.
CREATE UNIQUE INDEX report_templates_unique_idx
    ON report_templates (
        COALESCE(partner_id, '00000000-0000-0000-0000-000000000000'::uuid),
        code
    );

CREATE TABLE reports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id    UUID NOT NULL REFERENCES platforms(id),
    partner_id     UUID NOT NULL REFERENCES partners(id),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id  UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    template_id    UUID REFERENCES report_templates(id),
    report_type    TEXT NOT NULL,
    title          TEXT NOT NULL,
    parameters     JSONB NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT 'pending',   -- pending | generating | ready | failed | approved
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    generated_by   UUID REFERENCES users(id),
    generated_at   TIMESTAMPTZ,
    approved_by    UUID REFERENCES users(id),
    approved_at    TIMESTAMPTZ,
    version        INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX reports_engagement_idx ON reports(engagement_id);
CREATE INDEX reports_tenant_idx     ON reports(tenant_id);

CREATE TABLE report_sections (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    section_key TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT,
    order_idx   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE report_exports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    format      TEXT NOT NULL,    -- pdf | docx | xlsx | html | json | csv
    storage_url TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size_bytes  BIGINT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE report_approvals (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    approver_id UUID REFERENCES users(id),
    decision    TEXT NOT NULL,    -- approved | rejected
    note        TEXT,
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE report_download_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    export_id   UUID REFERENCES report_exports(id),
    user_id     UUID REFERENCES users(id),
    ip          INET,
    user_agent  TEXT,
    downloaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
