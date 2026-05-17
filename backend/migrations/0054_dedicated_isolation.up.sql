-- 0054_dedicated_isolation.up.sql
--
-- Tenants with isolation_mode='dedicated' get cryptographic +
-- physical-routing isolation on top of the platform's standard
-- RLS-based logical isolation:
--
--   1. A DEDICATED tenant_data_keys row whose DEK never wraps any
--      other tenant's data. Migration 0024 already requires one DEK
--      per tenant — but the KEK wrapping it is shared. Here we add
--      a kek_ref column so dedicated tenants can point at a tenant-
--      specific KEK (e.g. a per-tenant AWS KMS key alias) wrapping
--      ONLY their DEK.
--
--   2. Optional connection-string override per tenant so dedicated
--      tenants can be routed to a separate Postgres role (or even
--      a separate database) instead of sharing the API's main pool.
--      The dedicated_pool_dsn column is read by db.RouteForTenant
--      and looked up once on first request, cached per-process.
--
-- Convention: NULL / empty values fall back to the shared platform
-- defaults — so flipping a tenant from 'shared' to 'dedicated' is
-- safe (it activates the dedicated paths only when the operator
-- also populates the per-tenant overrides).

-- A) Per-tenant KEK reference (extends tenant_data_keys without
-- breaking the existing one-row-per-tenant constraint).
ALTER TABLE tenant_data_keys
    ADD COLUMN IF NOT EXISTS dedicated_kek_ref TEXT;

-- B) Per-tenant Postgres routing override. Sensitive: stored
-- separately and only readable by the connection-routing helper,
-- not the general application code path.
CREATE TABLE IF NOT EXISTS tenant_pool_routing (
    tenant_id          UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    dedicated_pool_dsn TEXT NOT NULL,        -- "host=... user=... password=... dbname=..."
    pool_kind          TEXT NOT NULL DEFAULT 'shared_role',
                       -- shared_role | dedicated_database | dedicated_schema
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenant_pool_routing_kind_idx
    ON tenant_pool_routing(pool_kind);

-- C) Audit trail for isolation-mode transitions. Flipping a tenant
-- from shared to dedicated is a customer-visible commitment (SLA,
-- contractual data-isolation guarantees); we record every such
-- transition with the actor and reason.
CREATE TABLE IF NOT EXISTS tenant_isolation_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_mode    TEXT NOT NULL,
    to_mode      TEXT NOT NULL,
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    reason       TEXT,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenant_isolation_history_tenant_idx
    ON tenant_isolation_history(tenant_id, changed_at DESC);
