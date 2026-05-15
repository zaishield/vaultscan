-- Seed: default platform, default partner, demo tenant
-- Blueprint §1.1 ZAISHIELD brand, §3 Cloud portal first-run

INSERT INTO platforms(id, name, slug)
VALUES ('00000000-0000-0000-0000-0000000000a1', 'ZAISHIELD', 'zaishield');

-- Default direct ZAISHIELD partner record (so all tenants always have a partner_id)
INSERT INTO partners(id, platform_id, type_id, name, slug, status)
SELECT '00000000-0000-0000-0000-0000000000b1',
       '00000000-0000-0000-0000-0000000000a1',
       id, 'ZAISHIELD Direct', 'zaishield-direct', 'active'
FROM partner_types WHERE code = 'direct';

INSERT INTO partner_branding(partner_id, product_name, primary_color, secondary_color,
                             support_email, sender_email, sender_name,
                             watermark_text, confidentiality_tag, legal_footer)
VALUES ('00000000-0000-0000-0000-0000000000b1',
        'ZAISHIELD VAULTSCAN', '#0F172A', '#38BDF8',
        'support@zaishield.com', 'no-reply@zaishield.com', 'ZAISHIELD VAULTSCAN',
        'CONFIDENTIAL', 'CONFIDENTIAL',
        '© ZAISHIELD - VAULTSCAN. All rights reserved.');

INSERT INTO partner_domains(partner_id, domain, is_primary)
VALUES ('00000000-0000-0000-0000-0000000000b1', 'vaultscan.zaishield.com', true),
       ('00000000-0000-0000-0000-0000000000b1', 'localhost',                false);

-- Wire every role to a sensible default permission set
WITH r AS (SELECT id, code FROM roles), p AS (SELECT id, code FROM permissions)
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM r, p WHERE
  -- ZAISHIELD super admin: everything
  (r.code = 'zaishield_super_admin') OR
  -- platform security admin: everything except partner CRUD branding
  (r.code = 'platform_security_admin' AND p.code NOT IN ('create_partner','manage_branding')) OR
  -- distributor admin
  (r.code = 'distributor_admin' AND p.code IN
     ('create_tenant','create_engagement','approve_scope','upload_authorization','view_findings',
      'generate_report','view_audit_logs','manage_branding','manage_agents')) OR
  -- reseller admin
  (r.code = 'reseller_admin' AND p.code IN
     ('create_tenant','create_engagement','approve_scope','upload_authorization','view_findings',
      'generate_report','view_audit_logs','manage_branding','manage_agents')) OR
  -- mssp manager
  (r.code = 'mssp_manager' AND p.code IN
     ('create_engagement','approve_scope','upload_authorization','create_scan_job',
      'approve_aggressive_scan','view_findings','edit_findings','request_retest','execute_retest',
      'generate_report','download_evidence','manage_agents','trigger_emergency_stop','view_audit_logs')) OR
  (r.code = 'mssp_analyst' AND p.code IN
     ('view_findings','edit_findings','request_retest','generate_report','download_evidence',
      'view_audit_logs')) OR
  (r.code = 'tenant_admin' AND p.code IN
     ('create_engagement','approve_scope','upload_authorization','create_scan_job',
      'view_findings','generate_report','download_evidence','manage_agents','trigger_emergency_stop',
      'view_audit_logs')) OR
  (r.code = 'engagement_manager' AND p.code IN
     ('create_scan_job','approve_scope','upload_authorization','view_findings','edit_findings',
      'request_retest','generate_report','download_evidence')) OR
  (r.code = 'pentester' AND p.code IN
     ('create_scan_job','view_findings','edit_findings','execute_retest','download_evidence')) OR
  (r.code = 'analyst' AND p.code IN
     ('view_findings','edit_findings','request_retest','generate_report')) OR
  (r.code = 'remediation_owner' AND p.code IN
     ('view_findings','edit_findings','request_retest')) OR
  (r.code = 'client_viewer' AND p.code IN
     ('view_findings','generate_report')) OR
  (r.code = 'auditor' AND p.code IN
     ('view_findings','view_audit_logs','generate_report')) OR
  (r.code = 'agent_installer' AND p.code IN
     ('manage_agents'));

-- Default scanner regions (Blueprint §5.4)
INSERT INTO scanner_node_registry(region, hostname, public_ip, capacity_jobs, cpu_cores, memory_mb,
                                   abuse_contact, reverse_dns, status)
VALUES
  ('ae','scan-ae-01.vaultscan.zaishield.com','203.0.113.10',8, 32,131072,
   'abuse@zaishield.com','scan-ae-01.vaultscan.zaishield.com','online'),
  ('eu','scan-eu-01.vaultscan.zaishield.com','203.0.113.20',8, 32,131072,
   'abuse@zaishield.com','scan-eu-01.vaultscan.zaishield.com','online'),
  ('in','scan-in-01.vaultscan.zaishield.com','203.0.113.30',8, 32,131072,
   'abuse@zaishield.com','scan-in-01.vaultscan.zaishield.com','online'),
  ('us','scan-us-01.vaultscan.zaishield.com','203.0.113.40',8, 32,131072,
   'abuse@zaishield.com','scan-us-01.vaultscan.zaishield.com','online'),
  ('sg','scan-sg-01.vaultscan.zaishield.com','203.0.113.50',8, 32,131072,
   'abuse@zaishield.com','scan-sg-01.vaultscan.zaishield.com','online');
