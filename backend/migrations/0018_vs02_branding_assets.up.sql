-- VS-02 deepening: partner-uploaded assets (logos, favicons, watermark
-- images) live in a dedicated table so branding rows stay small + diffable,
-- and the asset URLs can be CDN-signed independent of the metadata.

CREATE TABLE partner_brand_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id      UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    asset_type      TEXT NOT NULL,        -- logo_dark | logo_light | favicon | pdf_cover | watermark
    content_type    TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    storage_url     TEXT NOT NULL,        -- evidence vault URL
    width_px        INTEGER,
    height_px       INTEGER,
    uploaded_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (partner_id, asset_type)       -- one logo_dark per partner; replace by upsert
);
CREATE INDEX brand_assets_partner_idx ON partner_brand_assets(partner_id);

-- DNS verification records for each partner's sender domain. The portal's
-- email-templates UI can show "SPF: missing", "DKIM: aligned", etc. so
-- operators know why a send-test failed. Scheduled refresh happens out of
-- band; the verifier API populates this on demand.
CREATE TABLE partner_sender_dns (
    partner_id      UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL,
    spf_status      TEXT,                 -- pass | missing | misconfigured
    spf_record      TEXT,
    dkim_status     TEXT,
    dkim_selector   TEXT,
    dmarc_status    TEXT,
    dmarc_record    TEXT,
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (partner_id, domain)
);

-- ETag for the branding bundle so the portal can short-circuit re-fetches.
ALTER TABLE partner_branding ADD COLUMN IF NOT EXISTS bundle_etag TEXT;
