-- 0055_data_residency.up.sql
--
-- Data-residency declaration per tenant. Many enterprise customers
-- in EU/UK/UAE/IN require contractual guarantees that their data
-- stays inside a named region. We can't enforce that at the schema
-- level (the DB is wherever the operator deployed it) but we CAN:
--
--   1. Record the contractual region per tenant.
--   2. Refuse cross-region writes at the service layer when a
--      tenant pinned to "eu" appears on a request handled by a
--      pod running in "us" (api binary reads its own region from
--      VAULTSCAN_REGION and compares against the tenant's pin).
--   3. Surface the region in /api/v1/usage so customer support can
--      reference the binding contractually.
--
-- Convention: NULL means "no residency commitment" — legacy tenants
-- created before this column are not retroactively pinned. Operators
-- who want to upgrade legacy tenants do so via the PUT endpoint.
--
-- The residency check is "best-effort" in the sense that an operator
-- who runs all pods in a single region can't violate it; cross-region
-- deployments must run with VAULTSCAN_REGION set on every pod for the
-- service-layer gate to work.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS data_region TEXT;

-- Allowed values are an open set so a future region (af, latam, etc.)
-- doesn't require a schema change. The application layer validates
-- against a configured list at boot.
COMMENT ON COLUMN tenants.data_region IS
    'ISO 3166 region pin: ae|eu|uk|in|us|sg|au|jp|etc. NULL = no commitment.';

-- Audit transitions of the residency pin so contract changes are
-- traceable. Shares the same shape as tenant_isolation_history.
CREATE TABLE IF NOT EXISTS tenant_residency_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_region  TEXT,
    to_region    TEXT,
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    reason       TEXT,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenant_residency_history_tenant_idx
    ON tenant_residency_history(tenant_id, changed_at DESC);
