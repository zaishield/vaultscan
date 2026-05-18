-- 0058_compliance_gdpr_pci_expansion.down.sql
-- Reverses the 0058 seed inserts. Idempotent — safe to re-run.
DELETE FROM compliance_controls
 WHERE (framework, framework_version) = ('gdpr', '2016/679');

DELETE FROM compliance_controls
 WHERE framework = 'pci_dss'
   AND framework_version = '4.0'
   AND control_code IN ('1.2.6','3.5.1','6.3.2','7.2.5','8.3.6','10.2.1','10.5.1','12.10.1');
