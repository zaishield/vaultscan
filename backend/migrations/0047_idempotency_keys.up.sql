-- Idempotency-Key middleware store. Standard REST pattern: client
-- sends `Idempotency-Key: <uuid>` on a POST/PUT/PATCH; if we've seen
-- it before, we replay the cached response instead of executing
-- the side effect twice. Critical for safe client retries through
-- transient network failures.
--
-- Scope: keyed by (tenant_id, key). Two tenants can independently
-- use the same UUID literal; collisions can't bleed across tenants.
--
-- Lifecycle:
--   * Row created when middleware sees a new key
--     (request_hash + status = "in_flight").
--   * Filled in with response_status + response_body once the
--     downstream handler returns.
--   * Swept after 24h (default; see retention_hours config).
CREATE TABLE idempotency_keys (
    -- Composite PK so the same key cannot appear twice for a tenant.
    -- tenant_id is NULL for platform-scoped writes (e.g.
    -- createTenant by a platform_admin).
    tenant_id        UUID,
    key              TEXT NOT NULL,

    -- request_hash = sha256(method || ' ' || path || ' ' || body).
    -- A replay that hits the same key but with a different body is
    -- treated as a conflict (409) — caller has a bug or is reusing
    -- the key incorrectly. Without this, a malicious client could
    -- get its first request "executed" then replay a different
    -- payload and have us serve a misleading cached response.
    request_hash     BYTEA NOT NULL,

    -- "in_flight" while the handler is running; populated to the
    -- final HTTP status once the handler returns. in_flight rows
    -- short-circuit concurrent retries to a 409 so we never run
    -- the side effect twice.
    status           TEXT NOT NULL,

    response_status  INTEGER,
    response_body    BYTEA,
    response_headers JSONB,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at     TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '24 hours'),

    PRIMARY KEY (tenant_id, key)
);

-- The composite PK above uses tenant_id; NULLs are not deduplicated
-- by the PK index in Postgres. Add an additional unique index that
-- treats NULL as a real value via COALESCE so platform-scoped writes
-- still dedupe.
CREATE UNIQUE INDEX idempotency_keys_platform_idx
    ON idempotency_keys (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key);

-- Sweep query is "WHERE expires_at < now()" so index on expires_at
-- keeps the cron lightweight.
CREATE INDEX idempotency_keys_expires_idx ON idempotency_keys(expires_at);
