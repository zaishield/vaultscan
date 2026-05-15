-- VS-12 deepening: per-user dashboard layouts, SSE subscription tracking,
-- geo scan map data, compliance dashboard cache.

-- Per-user dashboard layouts. Each user can have multiple saved layouts
-- (executive, soc, risk, etc.). The widgets array carries position +
-- type + config — the frontend deserialises it into the grid.
CREATE TABLE user_dashboard_layouts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'executive',  -- executive | soc | risk | partner_msp | scope_admin
    is_default      BOOLEAN NOT NULL DEFAULT false,
    widgets         JSONB NOT NULL DEFAULT '[]',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, name)
);
CREATE INDEX user_dashboard_layouts_user_idx
    ON user_dashboard_layouts(user_id, role);

-- One default per user per role.
CREATE UNIQUE INDEX user_dashboard_layouts_default_unique
    ON user_dashboard_layouts(user_id, role)
    WHERE is_default = true;

-- SSE subscription registry. Tracks active live-update streams so an
-- operator can see who's connected + cap concurrent fan-out.
CREATE TABLE dashboard_sse_subscriptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    channel         TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ
);
CREATE INDEX dashboard_sse_active_idx
    ON dashboard_sse_subscriptions(tenant_id, channel)
    WHERE closed_at IS NULL;

-- Geo dimension for scanner_node_registry. Production seeds with real
-- coordinates; here we just create the column so the map endpoint
-- can read it.
ALTER TABLE scanner_node_registry ADD COLUMN IF NOT EXISTS latitude  NUMERIC(8,4);
ALTER TABLE scanner_node_registry ADD COLUMN IF NOT EXISTS longitude NUMERIC(8,4);
ALTER TABLE scanner_node_registry ADD COLUMN IF NOT EXISTS city      TEXT;
ALTER TABLE scanner_node_registry ADD COLUMN IF NOT EXISTS country   TEXT;

-- Seed coordinates for the regions we ship with so the geo map renders
-- something on a fresh install.
UPDATE scanner_node_registry SET latitude=25.2048, longitude=55.2708,
       city='Dubai', country='AE' WHERE region='ae' AND latitude IS NULL;
UPDATE scanner_node_registry SET latitude=52.5200, longitude=13.4050,
       city='Frankfurt', country='DE' WHERE region='eu' AND latitude IS NULL;
UPDATE scanner_node_registry SET latitude=19.0760, longitude=72.8777,
       city='Mumbai', country='IN' WHERE region='in' AND latitude IS NULL;
UPDATE scanner_node_registry SET latitude=37.7749, longitude=-122.4194,
       city='San Francisco', country='US' WHERE region='us' AND latitude IS NULL;
UPDATE scanner_node_registry SET latitude=1.3521,  longitude=103.8198,
       city='Singapore', country='SG' WHERE region='sg' AND latitude IS NULL;
UPDATE scanner_node_registry SET latitude=-26.2041, longitude=28.0473,
       city='Johannesburg', country='ZA' WHERE region='sa' AND latitude IS NULL;
UPDATE scanner_node_registry SET latitude=51.5074, longitude=-0.1278,
       city='London', country='GB' WHERE region='uk' AND latitude IS NULL;
