-- Reverses 0002_partners_branding.up.sql.
DROP TABLE IF EXISTS partner_branding_history CASCADE;
DROP TABLE IF EXISTS partner_domains           CASCADE;
DROP TABLE IF EXISTS partner_reseller_mapping  CASCADE;
DROP TABLE IF EXISTS partner_branding          CASCADE;
ALTER TABLE partners DROP COLUMN IF EXISTS parent_id;
