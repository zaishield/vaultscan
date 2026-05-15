-- VS-07 deepening: similarity clustering, severity overrides, suppression
-- rules, SARIF export support.
--
-- The exact-fingerprint dedup already collapses re-scans of the same
-- finding. Clusters group families ("Weak TLS on port {n}" across ports)
-- so the portal can hide 200 rows behind one expandable header. The
-- override + suppression engines run before the canonical Upsert so the
-- final row already carries any tenant-configured severity bump or auto-
-- false-positive flag — no separate "fix it up later" pass.

CREATE TABLE finding_clusters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cluster_key     TEXT NOT NULL,
    representative_title TEXT NOT NULL,
    scanner         TEXT NOT NULL,
    severity_max    TEXT NOT NULL DEFAULT 'info',
    member_count    INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, cluster_key)
);
CREATE INDEX finding_clusters_tenant_idx ON finding_clusters(tenant_id);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS cluster_id UUID
    REFERENCES finding_clusters(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS findings_cluster_idx ON findings(cluster_id)
    WHERE cluster_id IS NOT NULL;

-- Track when a tenant override bumped a finding's severity, so reports
-- can flag platform-vs-tenant-judgement deltas.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity_overridden_from TEXT;

-- Per-tenant severity override rules. First match wins; patterns are
-- regex against title (Postgres '~*' case-insensitive operator). A rule
-- with cve_pattern set bypasses title matching.
CREATE TABLE finding_severity_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    title_regex     TEXT,
    cve_pattern     TEXT,
    scanner_filter  TEXT,                       -- '' = any scanner
    new_severity    TEXT NOT NULL,              -- critical | high | medium | low | info
    reason          TEXT,
    priority        INTEGER NOT NULL DEFAULT 100,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX finding_severity_overrides_tenant_idx
    ON finding_severity_overrides(tenant_id, enabled, priority);

-- Per-tenant suppression rules — ingest-time auto-false-positive.
-- A typical rule: scanner=nmap + title_regex='port .* (closed|filtered)'
-- because we don't care about closed ports.
CREATE TABLE finding_suppression_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    title_regex     TEXT,
    cve_pattern     TEXT,
    scanner_filter  TEXT,
    asset_filter    TEXT,                       -- regex against asset value
    reason          TEXT NOT NULL,
    expires_at      TIMESTAMPTZ,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX finding_suppression_rules_tenant_idx
    ON finding_suppression_rules(tenant_id, enabled);

-- Stamp the suppression source on the finding so an auditor can answer
-- "why is this status=false_positive?".
ALTER TABLE findings ADD COLUMN IF NOT EXISTS suppression_rule_id UUID
    REFERENCES finding_suppression_rules(id) ON DELETE SET NULL;
