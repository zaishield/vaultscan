-- VS-04 deepening: asset relationships graph + fuzzy-dedup keys + cloud
-- inventory snapshots.

-- Asset relationship edges. Parent assets are "container" objects (a
-- domain owns subdomains; a Kubernetes cluster owns workloads). Allows
-- the portal to render a tree and the report engine to summarise risk
-- by ownership chain.
CREATE TABLE asset_relationships (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id     UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    child_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,    -- contains | depends_on | owns | hosts
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (parent_id, child_id, kind)
);
CREATE INDEX asset_relationships_parent_idx ON asset_relationships(parent_id);
CREATE INDEX asset_relationships_child_idx  ON asset_relationships(child_id);

-- Discovery runs link an asset to the scanner output that first turned
-- it up. Lets operators audit "where did this surface come from?"
ALTER TABLE asset_discovery_history ADD COLUMN IF NOT EXISTS scan_job_id UUID
    REFERENCES scan_jobs(id) ON DELETE SET NULL;
ALTER TABLE asset_discovery_history ADD COLUMN IF NOT EXISTS tool TEXT;
CREATE INDEX IF NOT EXISTS asset_discovery_scanjob_idx
    ON asset_discovery_history(scan_job_id) WHERE scan_job_id IS NOT NULL;

-- Fuzzy-dedup key: normalised lowercase value with leading 'www.' stripped
-- so 'WWW.Example.com', 'example.com', 'www.example.com' all collapse.
-- Maintained by a trigger so application code doesn't need to remember.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS dedup_key TEXT;

CREATE OR REPLACE FUNCTION vaultscan_asset_dedup_key() RETURNS trigger AS $$
BEGIN
  NEW.dedup_key := lower(regexp_replace(coalesce(NEW.value, ''), '^www\.', '', 'i'));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS assets_dedup_key_trigger ON assets;
CREATE TRIGGER assets_dedup_key_trigger
  BEFORE INSERT OR UPDATE OF value ON assets
  FOR EACH ROW EXECUTE FUNCTION vaultscan_asset_dedup_key();

-- Backfill for existing rows.
UPDATE assets SET dedup_key = lower(regexp_replace(coalesce(value, ''), '^www\.', '', 'i'))
 WHERE dedup_key IS NULL;

CREATE INDEX IF NOT EXISTS assets_dedup_key_idx ON assets(tenant_id, asset_type, dedup_key);
