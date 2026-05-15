-- Reverses 0010_seed_platform.up.sql. Seed data is lossy to reverse
-- in general (re-applying the up migration would re-create the rows).
-- We remove the specific seeded rows so a re-application doesn't hit
-- PK conflicts.

DELETE FROM scanner_node_registry
 WHERE region IN ('ae','eu','in','us','sg','sa','uk')
   AND hostname LIKE 'scan-%.vaultscan.zaishield.com';

DELETE FROM scan_profiles WHERE code LIKE 'external_%' OR code LIKE 'internal_%' OR code LIKE 'cloud_%';
DELETE FROM partner_branding WHERE partner_id IN
       (SELECT id FROM partners WHERE slug='zaishield-direct');
DELETE FROM partner_domains   WHERE partner_id IN
       (SELECT id FROM partners WHERE slug='zaishield-direct');
DELETE FROM partners   WHERE slug='zaishield-direct';
DELETE FROM platforms  WHERE slug='zaishield';
