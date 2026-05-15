-- VS-04 Asset Discovery & Management
-- Blueprint §16, §20.1

CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id),
    partner_id      UUID NOT NULL REFERENCES partners(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id)    ON DELETE CASCADE,
    engagement_id   UUID REFERENCES engagements(id)         ON DELETE SET NULL,
    asset_type      TEXT NOT NULL,    -- domain | subdomain | ip | cidr | api | webapp | server | database | cloud_resource | container | k8s_cluster | mobile_app | repository | ssl_certificate
    name            TEXT NOT NULL,
    value           TEXT NOT NULL,    -- canonical address (FQDN, IP, ARN, repo URL, etc.)
    plane           TEXT NOT NULL DEFAULT 'external',  -- external | internal
    criticality     TEXT NOT NULL DEFAULT 'unknown',   -- critical | high | medium | low | unknown
    owner           TEXT,
    environment     TEXT,                              -- prod | staging | dev | dr
    cloud_provider  TEXT,                              -- aws | azure | gcp | other
    tags            JSONB NOT NULL DEFAULT '[]',
    metadata        JSONB NOT NULL DEFAULT '{}',
    discovered_via  TEXT NOT NULL DEFAULT 'manual',    -- manual | csv | api | external_discovery | agent_discovery | cloud_connector
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX assets_tenant_idx     ON assets(tenant_id);
CREATE INDEX assets_engagement_idx ON assets(engagement_id);
CREATE INDEX assets_type_idx       ON assets(asset_type);
CREATE INDEX assets_plane_idx      ON assets(plane);
CREATE UNIQUE INDEX assets_unique_value_idx ON assets(tenant_id, asset_type, value);

CREATE TABLE asset_services (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id     UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port         INTEGER,
    protocol     TEXT,
    service      TEXT,
    product      TEXT,
    version      TEXT,
    banner       TEXT,
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX asset_services_asset_idx ON asset_services(asset_id);

CREATE TABLE asset_tags (
    asset_id  UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag       TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag)
);

CREATE TABLE asset_discovery_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
