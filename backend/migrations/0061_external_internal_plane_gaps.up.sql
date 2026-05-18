-- 0061_external_internal_plane_gaps.up.sql
--
-- Closes the remaining real-functionality gaps the audit pass
-- surfaced on the external and internal planes. Each table below
-- backs an endpoint added in the same change set; the API code is
-- in backend/internal/api/ + handlers_{platform,billing,sso,scim,
-- impersonation,compliance}.go.

-- ============================================================
-- EXTERNAL plane: customer-facing self-service additions
-- ============================================================

-- Plan-change requests. Customer admin files a request; sales /
-- finance reviews + approves. Not fully self-serve (the operator
-- holds the actual plan change because pricing is contractual),
-- but removes the "email your CSM and wait" loop.
CREATE TABLE plan_change_requests (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id     UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    requested_by   UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    current_plan   TEXT NOT NULL,
    requested_plan TEXT NOT NULL,
    note           TEXT,
    status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at     TIMESTAMPTZ,
    decided_by     UUID REFERENCES users(id),
    decision_note  TEXT
);
CREATE INDEX plan_change_requests_partner_idx
    ON plan_change_requests(partner_id, requested_at DESC);
CREATE INDEX plan_change_requests_pending_idx
    ON plan_change_requests(status, requested_at)
    WHERE status = 'pending';

-- Per-tenant SSO configuration. SAML / OIDC IdP federation lives
-- here so customer admins can self-serve their identity-provider
-- trust setup (previously buried under the branding endpoint).
CREATE TABLE tenant_sso_config (
    tenant_id        UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    provider_type    TEXT NOT NULL
                     CHECK (provider_type IN ('saml', 'oidc', 'none')),
    enabled          BOOLEAN NOT NULL DEFAULT false,
    metadata_xml     TEXT,                    -- SAML SP metadata
    discovery_url    TEXT,                    -- OIDC /.well-known/openid-configuration
    client_id        TEXT,                    -- OIDC client_id
    client_secret    TEXT,                    -- OIDC client_secret (operator should wrap with KMS)
    claim_mapping    JSONB NOT NULL DEFAULT '{
                       "email": "email",
                       "name":  "name",
                       "roles": "groups"
                     }'::jsonb,
    last_tested_at   TIMESTAMPTZ,
    last_test_ok     BOOLEAN,
    last_test_error  TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenant_sso_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_sso_config FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_sso_config_tenant_isolation
  ON tenant_sso_config
  USING (
    tenant_id::text = current_setting('vaultscan.tenant_id', true)
    OR current_setting('vaultscan.tenant_id', true) = ''
    OR current_setting('vaultscan.tenant_id', true) IS NULL
  );

-- Per-tenant SCIM token. The token plaintext is shown ONCE on
-- creation and never again (bcrypt-hashed at rest). Customer admins
-- generate / rotate / revoke tokens self-serve.
CREATE TABLE tenant_scim_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL,           -- bcrypt
    label         TEXT NOT NULL,           -- operator-supplied (e.g. "Okta prod")
    created_by    UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,             -- nullable = no expiry
    last_used_at  TIMESTAMPTZ,
    last_used_ip  INET,
    revoked_at    TIMESTAMPTZ,
    revoked_by    UUID REFERENCES users(id),
    UNIQUE (tenant_id, label)
);
CREATE INDEX tenant_scim_tokens_tenant_idx
    ON tenant_scim_tokens(tenant_id)
    WHERE revoked_at IS NULL;
ALTER TABLE tenant_scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_scim_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scim_tokens_tenant_isolation
  ON tenant_scim_tokens
  USING (
    tenant_id::text = current_setting('vaultscan.tenant_id', true)
    OR current_setting('vaultscan.tenant_id', true) = ''
    OR current_setting('vaultscan.tenant_id', true) IS NULL
  );

-- ============================================================
-- INTERNAL plane: ops + support + finance + admin additions
-- ============================================================

-- Support-engineer impersonation. Every impersonation session
-- captures: who, target, scope, ticket reference, started + ended.
-- The JWT minted under this session carries `impersonation_session_id`
-- so every subsequent API call's audit row attributes BOTH the
-- operator AND the impersonated user. There is no way to disable
-- this audit trail from the impersonating JWT.
CREATE TABLE support_impersonation_sessions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id    UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_tenant  UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    ticket_ref     TEXT NOT NULL,           -- support ticket ID / change ticket
    reason         TEXT NOT NULL,           -- short description
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,    -- hard cap; default 60 min
    ended_at       TIMESTAMPTZ,
    ended_by       UUID REFERENCES users(id),
    request_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX support_impersonation_active_idx
    ON support_impersonation_sessions(operator_id, started_at DESC)
    WHERE ended_at IS NULL;

-- Tenant lifecycle: quarantine before hard-delete. Tenant marked
-- for deletion enters a 7-day window during which the cron-runner's
-- new tenant_purge_swept_quarantines task runs. Cancellable until
-- the window closes.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS quarantine_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS quarantine_initiated_by UUID REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS quarantine_reason TEXT;

CREATE INDEX tenants_quarantined_idx
    ON tenants(quarantine_started_at)
    WHERE quarantine_started_at IS NOT NULL;

-- Partner-migration history. Tenants can be moved between partners
-- (acquisition, MSSP swap, reorg). Each move records who, when,
-- from, to + carries forward in the audit trail.
CREATE TABLE tenant_partner_migrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_partner_id UUID NOT NULL REFERENCES partners(id),
    to_partner_id   UUID NOT NULL REFERENCES partners(id),
    migrated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    migrated_by     UUID NOT NULL REFERENCES users(id),
    reason          TEXT NOT NULL
);
CREATE INDEX tenant_partner_migrations_tenant_idx
    ON tenant_partner_migrations(tenant_id, migrated_at DESC);

-- Compliance evaluation snapshots. A rollup endpoint returns
-- per-framework coverage % at a point in time. Today the data is
-- computed on every call; this materialised snapshot lets us
-- answer "what did our SOC2 coverage look like on 2026-04-01" for
-- auditor walkthroughs.
CREATE TABLE compliance_rollup_snapshots (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    framework      TEXT NOT NULL,
    framework_ver  TEXT NOT NULL,
    snapshot_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    controls_total INTEGER NOT NULL,
    controls_pass  INTEGER NOT NULL,
    controls_fail  INTEGER NOT NULL,
    controls_manual INTEGER NOT NULL,
    coverage_pct   NUMERIC(5,2) NOT NULL,
    breakdown_json JSONB NOT NULL
);
CREATE INDEX compliance_rollup_snapshots_tenant_fw_idx
    ON compliance_rollup_snapshots(tenant_id, framework, snapshot_at DESC);
ALTER TABLE compliance_rollup_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_rollup_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY compliance_rollup_snapshots_tenant_isolation
  ON compliance_rollup_snapshots
  USING (
    tenant_id::text = current_setting('vaultscan.tenant_id', true)
    OR current_setting('vaultscan.tenant_id', true) = ''
    OR current_setting('vaultscan.tenant_id', true) IS NULL
  );

-- Plan-change history. Independent of plan_change_requests — this
-- tracks the ACTUAL plan transitions (operator-initiated OR
-- request-approval-driven). Drives the finance dashboard's
-- "subscriptions over time" view and supports SLA-credit pro-
-- ration.
CREATE TABLE partner_plan_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id   UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    from_plan    TEXT,
    to_plan      TEXT NOT NULL,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    changed_by   UUID REFERENCES users(id),
    request_id   UUID REFERENCES plan_change_requests(id),
    note         TEXT
);
CREATE INDEX partner_plan_history_partner_idx
    ON partner_plan_history(partner_id, changed_at DESC);

-- Usage credit / adjustment table (finance ops). Allows manual
-- credits (incident SLA credits, sales-negotiated allowances)
-- without an out-of-band SQL UPDATE.
CREATE TABLE billing_usage_adjustments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id    UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    month         DATE NOT NULL,                  -- normalised to month-start
    metric        TEXT NOT NULL,                  -- e.g. 'scans_run', 'users_active'
    delta         INTEGER NOT NULL,               -- positive = credit (reduces usage); negative = surcharge
    reason        TEXT NOT NULL,                  -- e.g. 'SLA credit — incident INC-2026-04-19'
    ticket_ref    TEXT,                           -- support/CRM ticket
    created_by    UUID NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX billing_usage_adjustments_partner_month_idx
    ON billing_usage_adjustments(partner_id, month DESC);
