-- VS-07 Findings Engine / VS-08 Evidence Vault
-- Blueprint §17, §18, §20

CREATE TABLE findings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id       UUID NOT NULL REFERENCES platforms(id),
    partner_id        UUID NOT NULL REFERENCES partners(id),
    tenant_id         UUID NOT NULL REFERENCES tenants(id)    ON DELETE CASCADE,
    engagement_id     UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_id          UUID REFERENCES assets(id) ON DELETE SET NULL,
    scan_job_id       UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    title             TEXT NOT NULL,
    description       TEXT,
    severity          TEXT NOT NULL,        -- critical | high | medium | low | info
    confidence        TEXT NOT NULL DEFAULT 'medium',  -- low | medium | high
    cvss_score        NUMERIC(3,1),
    cvss_vector       TEXT,
    cwe               TEXT,
    cve               TEXT,
    scanner           TEXT NOT NULL,
    scan_type         TEXT NOT NULL,
    affected_endpoint TEXT,
    port              INTEGER,
    protocol          TEXT,
    evidence_summary  TEXT,
    business_impact   TEXT,
    technical_impact  TEXT,
    remediation       TEXT,
    "references"      JSONB NOT NULL DEFAULT '[]',     -- quoted: 'references' is a reserved word
    status            TEXT NOT NULL DEFAULT 'open',
        -- open | triaged | assigned | in_progress | risk_accepted | false_positive
        -- | remediated | retest_requested | retest_passed | retest_failed | closed
    assigned_to       UUID REFERENCES users(id),
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    dedup_fingerprint TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX findings_tenant_idx     ON findings(tenant_id);
CREATE INDEX findings_engagement_idx ON findings(engagement_id);
CREATE INDEX findings_asset_idx      ON findings(asset_id);
CREATE INDEX findings_severity_idx   ON findings(severity);
CREATE INDEX findings_status_idx     ON findings(status);
CREATE UNIQUE INDEX findings_dedup_idx ON findings(tenant_id, dedup_fingerprint);

CREATE TABLE finding_status_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_status TEXT,
    to_status   TEXT NOT NULL,
    changed_by  UUID REFERENCES users(id),
    note        TEXT,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX finding_status_history_finding_idx ON finding_status_history(finding_id, changed_at DESC);

CREATE TABLE finding_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES users(id),
    body        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Evidence vault
CREATE TABLE finding_evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    partner_id      UUID NOT NULL REFERENCES partners(id),
    finding_id      UUID REFERENCES findings(id) ON DELETE CASCADE,
    engagement_id   UUID REFERENCES engagements(id) ON DELETE SET NULL,
    scan_job_id     UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    evidence_type   TEXT NOT NULL,    -- screenshot | raw_output | http_request | http_response | tls_output | ad_graph | report | manual
    storage_url     TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    content_type    TEXT NOT NULL,
    encrypted       BOOLEAN NOT NULL DEFAULT true,
    immutable_until TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    uploaded_by     UUID REFERENCES users(id),
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX evidence_tenant_idx    ON finding_evidence(tenant_id);
CREATE INDEX evidence_finding_idx   ON finding_evidence(finding_id);
CREATE INDEX evidence_engagement_idx ON finding_evidence(engagement_id);

CREATE TABLE evidence_access_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id   UUID NOT NULL REFERENCES finding_evidence(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(id),
    action        TEXT NOT NULL,    -- view | download | upload | delete_attempt
    ip            INET,
    user_agent    TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_access_evidence_idx ON evidence_access_logs(evidence_id, occurred_at DESC);
