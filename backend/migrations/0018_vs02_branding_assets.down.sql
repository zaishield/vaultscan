-- Reverses 0018_vs02_branding_assets.up.sql.
ALTER TABLE partner_branding DROP COLUMN IF EXISTS bundle_etag;
DROP TABLE IF EXISTS partner_sender_dns   CASCADE;
DROP TABLE IF EXISTS partner_brand_assets CASCADE;
