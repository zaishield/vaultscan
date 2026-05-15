-- Blueprint §14 (discovery enrichment) + §16 (vulnerability enrichment) +
-- §21 (cloud posture) + §23 (notification engine) — all the read-side
-- and async-delivery surfaces that turn the platform from "we scan"
-- into "we know what other tools have already said about your stack".

-- ===========================================================================
-- §14 Discovery enrichment
-- ===========================================================================
--
-- Inbound feeds (Shodan / Censys / passive DNS / CT logs) per tenant. The
-- platform pulls a JSON dump on a schedule and writes enriched rows that
-- amend the asset graph.

CREATE TABLE external_data_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,              -- shodan | censys | passive_dns | ct_log
    api_key_ref     TEXT,                       -- pointer into secrets store; never plaintext
    enabled         BOOLEAN NOT NULL DEFAULT true,
    poll_interval_minutes INTEGER NOT NULL DEFAULT 60,
    last_polled_at  TIMESTAMPTZ,
    last_error      TEXT,
    config          JSONB NOT NULL DEFAULT '{}', -- per-source extras (search dorks etc.)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source)
);
CREATE INDEX external_data_sources_due_idx
    ON external_data_sources(tenant_id, last_polled_at) WHERE enabled = true;

-- Asset-level enrichment from any of the external sources. One row per
-- (asset_id, source, attribute) so a single asset can carry data from
-- multiple sources without merging conflicts.
CREATE TABLE asset_enrichments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source        TEXT NOT NULL,
    attribute     TEXT NOT NULL,                  -- open_ports | services | ssl_cert | http_title | banner | ja3
    value         JSONB NOT NULL,
    confidence    NUMERIC(3,2) NOT NULL DEFAULT 1.00,
    observed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, source, attribute)
);
CREATE INDEX asset_enrichments_asset_idx ON asset_enrichments(asset_id);

-- Certificate-transparency log entries discovered for tenant domains.
-- These often surface subdomains attackers know about that the customer
-- doesn't. The deduplication key is (tenant_id, lower(common_name), serial).
CREATE TABLE ct_log_entries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    common_name   TEXT NOT NULL,
    san_names     JSONB NOT NULL DEFAULT '[]',
    issuer        TEXT,
    serial        TEXT,
    not_before    TIMESTAMPTZ,
    not_after     TIMESTAMPTZ,
    log_url       TEXT,
    seen_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ct_log_entries_dedup_idx
    ON ct_log_entries(tenant_id, lower(common_name), COALESCE(serial,''));
CREATE INDEX ct_log_entries_tenant_idx ON ct_log_entries(tenant_id, seen_at DESC);

-- ===========================================================================
-- §16 Vulnerability enrichment
-- ===========================================================================
--
-- Reference data the findings engine consults at ingest-time:
--   * NVD CVSS    — base score + vector
--   * EPSS        — exploit-probability score (0..1)
--   * CISA KEV    — known-exploited flag + due date
--   * vendor patch availability (vendor-fed, partner-fed)

CREATE TABLE cve_metadata (
    cve_id            TEXT PRIMARY KEY,            -- CVE-YYYY-NNNN+
    cvss_score        NUMERIC(3,1),                -- 0.0..10.0
    cvss_vector       TEXT,
    cvss_severity     TEXT,                        -- LOW | MEDIUM | HIGH | CRITICAL
    epss_score        NUMERIC(5,4),                -- 0.0000..1.0000
    epss_percentile   NUMERIC(5,4),
    kev_flagged       BOOLEAN NOT NULL DEFAULT false,
    kev_due_date      DATE,                        -- federal-agency remediation deadline
    kev_ransomware    BOOLEAN NOT NULL DEFAULT false,
    summary           TEXT,
    "references"      JSONB NOT NULL DEFAULT '[]',
    published_at      TIMESTAMPTZ,
    last_modified_at  TIMESTAMPTZ,
    refreshed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cve_metadata_kev_idx ON cve_metadata(kev_flagged) WHERE kev_flagged = true;
CREATE INDEX cve_metadata_epss_idx ON cve_metadata(epss_score DESC);

-- Vendor patch advisories — when a vendor publishes a fix, we link
-- their advisory URL so the remediation_owner has a one-click path.
CREATE TABLE vendor_advisories (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id           TEXT NOT NULL REFERENCES cve_metadata(cve_id) ON DELETE CASCADE,
    vendor           TEXT NOT NULL,
    advisory_url     TEXT NOT NULL,
    patch_available  BOOLEAN NOT NULL DEFAULT false,
    fixed_versions   JSONB NOT NULL DEFAULT '[]',
    workarounds      TEXT,
    published_at     TIMESTAMPTZ,
    UNIQUE (cve_id, vendor)
);

-- Refresh sources — the cron-runner walks this table to know which
-- feeds to refresh and when.
CREATE TABLE vuln_data_sources (
    name              TEXT PRIMARY KEY,             -- nvd | epss | kev
    feed_url          TEXT NOT NULL,
    poll_interval_hours INTEGER NOT NULL DEFAULT 24,
    last_polled_at    TIMESTAMPTZ,
    last_error        TEXT,
    rows_loaded       INTEGER NOT NULL DEFAULT 0
);
INSERT INTO vuln_data_sources(name, feed_url, poll_interval_hours) VALUES
    ('nvd',  'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz', 24),
    ('epss', 'https://epss.cyentia.com/epss_scores-current.csv.gz',                24),
    ('kev',  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 24);

-- ===========================================================================
-- §21 Cloud posture
-- ===========================================================================
--
-- Each cloud account a tenant connects gets one row + a chain of
-- snapshots. Drift = differences between consecutive snapshots
-- against the CIS baseline.

CREATE TABLE cloud_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,                  -- aws | azure | gcp | oci | linode
    account_label   TEXT NOT NULL,                  -- friendly: "prod", "qa"
    external_id     TEXT NOT NULL,                  -- AWS account id, Azure subscription, GCP project
    credential_ref  TEXT NOT NULL,                  -- pointer into secrets store
    role_arn        TEXT,                           -- AWS only
    regions         JSONB NOT NULL DEFAULT '[]',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_snapshot_at TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, external_id)
);

CREATE TABLE cloud_posture_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    snapshot_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    findings        JSONB NOT NULL,                 -- normalized per-control results
    overall_score   NUMERIC(5,2)                    -- 0..100; weighted CIS posture
);
CREATE INDEX cloud_posture_snapshots_recent_idx
    ON cloud_posture_snapshots(account_id, snapshot_at DESC);

-- Drift events — delta between snapshot N and N-1 for any control
-- that changed state. Helps the dashboard surface "this got worse".
CREATE TABLE cloud_drift_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    control_id      TEXT NOT NULL,                  -- e.g. CIS-AWS-1.5
    direction       TEXT NOT NULL,                  -- improved | regressed
    previous_state  TEXT NOT NULL,
    current_state   TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cloud_drift_recent_idx
    ON cloud_drift_events(account_id, detected_at DESC);

-- ===========================================================================
-- §23 Notification engine
-- ===========================================================================
--
-- Outbound delivery queue with per-channel adapters. SMS, voice (PD),
-- email all flow through this queue so a single dashboard shows
-- failures by channel.

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,                  -- email | sms | pagerduty | webhook
    label           TEXT NOT NULL,                  -- "soc-on-call", "ciso-direct"
    config          JSONB NOT NULL DEFAULT '{}',    -- {"to":"+1...", "service_key":"..."}
    secret_ref      TEXT,                            -- pointer to secret if needed
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, label)
);

CREATE TABLE notification_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id      UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    priority        TEXT NOT NULL DEFAULT 'normal', -- low | normal | high | urgent
    attempt         INTEGER NOT NULL DEFAULT 0,
    state           TEXT NOT NULL DEFAULT 'pending',-- pending | delivered | failed | quarantined
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    payload         JSONB NOT NULL DEFAULT '{}',    -- finding_id, scan_job_id, etc.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);
CREATE INDEX notification_queue_due_idx
    ON notification_queue(next_attempt_at)
    WHERE state IN ('pending', 'failed');
