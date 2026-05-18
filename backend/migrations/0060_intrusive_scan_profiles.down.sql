-- 0060_intrusive_scan_profiles.down.sql
DELETE FROM scan_profiles
 WHERE code IN (
   'external_web_content_discovery',
   'devsecops_sast_secrets',
   'external_deep_pt'
 );
