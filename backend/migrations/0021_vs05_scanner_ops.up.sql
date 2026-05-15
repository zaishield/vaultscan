-- VS-05 deepening: external scanner farm operations.
--
-- Adds the surface a regional scanner operator actually runs day-to-day:
--   * scanner_node_health     — heartbeat + load + auto-degrade tracking
--   * scanner_region_quotas   — per-region cap on concurrent dispatched/running jobs
--   * scanner_pull_credentials — per-region per-registry image-pull secrets (encrypted)
--   * scanner_network_policies — egress allow-list rendered into K8s NetworkPolicy YAML
--
-- The picker in scanorch/nodes.go consults health + quota every dispatch, so
-- a node that has stopped heart-beating or a region that's at its cap fails
-- closed instead of silently overscheduling. See Blueprint §12.4-12.6.

-- Per-node operational snapshot. Distinct from scanner_node_registry so we
-- can rewrite this row at heartbeat speed (every 30s) without churning the
-- registry table the picker reads from.
CREATE TABLE scanner_node_health (
    node_id              UUID PRIMARY KEY REFERENCES scanner_node_registry(id) ON DELETE CASCADE,
    last_heartbeat_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error           TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    inflight_jobs        INTEGER NOT NULL DEFAULT 0,
    load_avg             NUMERIC(5,2),       -- 0.00 - 99.99
    image_pulls_failed   INTEGER NOT NULL DEFAULT 0,
    kernel_version       TEXT,
    scanner_version      TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-region cap. Production wants something like "us=12 simultaneous jobs"
-- so a runaway tenant can't drown a region. When NULL or absent, no cap.
CREATE TABLE scanner_region_quotas (
    region                 TEXT PRIMARY KEY,
    max_concurrent_jobs    INTEGER NOT NULL CHECK (max_concurrent_jobs > 0),
    reserved_for_platform  INTEGER NOT NULL DEFAULT 0,  -- e.g. 2 slots for ZAISHIELD's own scans
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-region, per-registry image-pull secret. Encrypted blob — the layer
-- above (secrets package) handles AES-GCM with the platform master key.
CREATE TABLE scanner_pull_credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region            TEXT NOT NULL,
    registry_host     TEXT NOT NULL,                       -- registry.zaishield.com, ghcr.io, ...
    docker_username   TEXT NOT NULL,
    encrypted_secret  BYTEA NOT NULL,                      -- AES-256-GCM(docker password)
    encryption_key_id TEXT NOT NULL,                       -- which master key wrapped it
    created_by        UUID REFERENCES users(id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at        TIMESTAMPTZ,
    UNIQUE (region, registry_host)
);

-- Per-region network policy. The list of CIDR/port pairs the scanner pods
-- are allowed to egress to. Used to render K8s NetworkPolicy at deploy
-- time AND audit-record at dispatch time so a stale policy can be detected.
CREATE TABLE scanner_network_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region          TEXT NOT NULL,
    name            TEXT NOT NULL,            -- "allow-https-out", "allow-dns"
    cidrs           JSONB NOT NULL DEFAULT '[]',   -- ["0.0.0.0/0"] or specific
    ports           JSONB NOT NULL DEFAULT '[]',   -- [{"port":443,"protocol":"TCP"}]
    direction       TEXT NOT NULL DEFAULT 'egress',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (region, name)
);

-- A regional auto-failover audit row. Every time a node is marked degraded
-- (consecutive heartbeat misses, image-pull failures crossing threshold),
-- we record why so an operator can later answer "why did region X drop a
-- node at 03:14?".
CREATE TABLE scanner_node_failovers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id      UUID NOT NULL REFERENCES scanner_node_registry(id) ON DELETE CASCADE,
    region       TEXT NOT NULL,
    reason       TEXT NOT NULL,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX scanner_node_failovers_region_idx
    ON scanner_node_failovers(region, triggered_at DESC);

-- Seed a sane default health row for every node already in the registry
-- so the picker doesn't immediately mark the dev seed nodes "degraded".
INSERT INTO scanner_node_health(node_id, last_heartbeat_at, inflight_jobs)
SELECT id, now(), 0 FROM scanner_node_registry
ON CONFLICT (node_id) DO NOTHING;

-- Seed a generous default region quota for the regions the registry
-- already references — keeps fresh installs from failing closed on the
-- first scan submission while still making the cap easy to lower per
-- region from the admin portal.
INSERT INTO scanner_region_quotas(region, max_concurrent_jobs, reserved_for_platform)
SELECT DISTINCT region, 32, 2 FROM scanner_node_registry
ON CONFLICT (region) DO NOTHING;

-- Default egress policy: HTTPS-out + DNS-out, anywhere. Operators tighten
-- per-region after they decide what's reachable.
INSERT INTO scanner_network_policies(region, name, cidrs, ports, direction)
SELECT DISTINCT region, 'allow-https-out',
       '["0.0.0.0/0"]'::jsonb,
       '[{"port":443,"protocol":"TCP"},{"port":80,"protocol":"TCP"}]'::jsonb,
       'egress'
  FROM scanner_node_registry
ON CONFLICT (region, name) DO NOTHING;

INSERT INTO scanner_network_policies(region, name, cidrs, ports, direction)
SELECT DISTINCT region, 'allow-dns-out',
       '["0.0.0.0/0"]'::jsonb,
       '[{"port":53,"protocol":"UDP"},{"port":53,"protocol":"TCP"}]'::jsonb,
       'egress'
  FROM scanner_node_registry
ON CONFLICT (region, name) DO NOTHING;
