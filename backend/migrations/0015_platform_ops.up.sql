-- VS-10 reporting approval workflow needs a clear gate before download:
-- approval is mandated when a partner enables the feature flag
-- 'reports.approval_required'. The reports table already has
-- requires_approval; ensure it defaults to that flag's value on insert.
-- No schema change — the application sets the field at generate time.

-- VS-11 integration deliveries already have the columns we need for the
-- health view; add an index for the dashboard's "last 5 minutes failure
-- rate" query.
CREATE INDEX IF NOT EXISTS integration_deliveries_recent_idx
    ON integration_deliveries(integration_id, created_at DESC);

-- VS-03 blackout windows: rules_of_engagement already supports
-- scan_window_start/end + days_of_week; add an explicit blackouts column
-- so operators can list "never scan on Black Friday" without abusing the
-- weekly window.
ALTER TABLE rules_of_engagement ADD COLUMN IF NOT EXISTS blackouts JSONB
    NOT NULL DEFAULT '[]';
-- Each entry: {"label": "Black Friday 2026", "starts_at": "...", "ends_at": "..."}.

-- VS-12 drill-down: dashboard cards link to filtered finding / scan-job
-- lists. We add a materialised denormalisation table so the partner
-- aggregations stay fast even with thousands of tenants.
CREATE TABLE IF NOT EXISTS partner_dashboard_rollup (
    partner_id              UUID PRIMARY KEY REFERENCES partners(id) ON DELETE CASCADE,
    customers_managed       INTEGER NOT NULL DEFAULT 0,
    active_tenants          INTEGER NOT NULL DEFAULT 0,
    active_agents           INTEGER NOT NULL DEFAULT 0,
    scan_usage_30d          INTEGER NOT NULL DEFAULT 0,
    open_critical_findings  INTEGER NOT NULL DEFAULT 0,
    expiring_engagements    INTEGER NOT NULL DEFAULT 0,
    refreshed_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
