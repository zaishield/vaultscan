-- Reverses 0011_zaishield_brand.up.sql. The up just updates the
-- existing seed row; we restore generic defaults so a re-apply is a
-- clean overwrite.
UPDATE partner_branding
   SET primary_color = NULL, accent_color = NULL,
       logo_url = NULL, dark_logo_url = NULL, favicon_url = NULL,
       product_name = 'VAULTSCAN'
 WHERE partner_id IN (SELECT id FROM partners WHERE slug='zaishield-direct');
