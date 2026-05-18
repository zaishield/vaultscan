-- 0058_compliance_gdpr_pci_expansion.up.sql
--
-- Pre-seeded compliance control mappings for GDPR (Articles relevant
-- to a SaaS processor) + expanded PCI DSS 4.0 (the controls the
-- platform actually evidences for the customer; gaps explicitly
-- documented).
--
-- Engineering note: these mappings are an OPINIONATED baseline.
-- Customer auditors may map differently — the rows here exist so
-- the platform has SOMETHING to evaluate on day-1; tenants are
-- expected to override per their auditor's interpretation via
-- the `compliance_evidence` table.

-- ----- GDPR (EU 2016/679) -------------------------------------------
-- 13 articles directly mappable to platform behaviour. Articles not
-- listed (e.g. Art. 25, 27, 36) are organisational, not technical —
-- the platform can't evidence them automatically.
INSERT INTO compliance_controls (
  framework, framework_version, control_code,
  title, description, evidence_query, automation_tier
) VALUES
  ('gdpr', '2016/679', 'Art-5-1-a',
   'Lawfulness, fairness, transparency',
   'Processing is lawful + transparent. Tenants document the legal basis in the engagement; platform records who triggered each processing operation.',
   'audit_logs', 'semi_automated'),

  ('gdpr', '2016/679', 'Art-5-1-c',
   'Data minimisation',
   'Personal data collected is adequate, relevant, and limited. Platform redacts PII from logs; evidence-pack export only includes the subject''s data.',
   'evidence', 'automated'),

  ('gdpr', '2016/679', 'Art-5-1-e',
   'Storage limitation',
   'Data kept no longer than necessary. Per-tenant retention via cron task evidence.SweepExpired + finding-history partition rollover.',
   'retention', 'automated'),

  ('gdpr', '2016/679', 'Art-5-1-f',
   'Integrity and confidentiality',
   'Processing ensures appropriate security. Evidence vault encrypts at rest (per-tenant DEK); transit is TLS 1.2+; access audited.',
   'tenant_data_keys', 'automated'),

  ('gdpr', '2016/679', 'Art-12-Art-15',
   'Right of access (data subject access request)',
   'Provide a copy of personal data on subject request within 30 days. Platform supports via /api/v1/users/{id}/export.',
   'audit_logs', 'semi_automated'),

  ('gdpr', '2016/679', 'Art-16',
   'Right to rectification',
   'Subject can correct inaccurate data. Platform: /api/v1/users/{id} PATCH; audit row records who + when.',
   'audit_logs', 'semi_automated'),

  ('gdpr', '2016/679', 'Art-17',
   'Right to erasure (right to be forgotten)',
   'Subject can request deletion. Platform: /api/v1/users/{id}/erase pseudonymises across users + login_events + token_revocations + emits audit. See gdpr-erasure.md runbook.',
   'audit_logs', 'automated'),

  ('gdpr', '2016/679', 'Art-20',
   'Right to data portability',
   'Subject can request machine-readable export of their data. Platform: /api/v1/users/{id}/export returns JSON.',
   'manual', 'semi_automated'),

  ('gdpr', '2016/679', 'Art-25',
   'Data protection by design and default',
   'Technical / organisational measures baked in. Platform: residency pin, per-tenant DEK, RLS, audit chain, encrypted backups.',
   'manual', 'manual'),

  ('gdpr', '2016/679', 'Art-28',
   'Data processor obligations (sub-processor list)',
   'Processor maintains list of sub-processors + supports DPA. Platform: documented in /docs/operations/data-processing-addendum-template.md.',
   'manual', 'manual'),

  ('gdpr', '2016/679', 'Art-30',
   'Records of processing activities',
   'Maintain a register of processing operations. Platform: audit_logs is the substrate; export-via-/api/v1/audit/export.',
   'audit_logs', 'automated'),

  ('gdpr', '2016/679', 'Art-32',
   'Security of processing',
   'Implement appropriate security. Platform: encryption-at-rest, encryption-in-transit, pseudonymisation, integrity tests, restore drill.',
   'tenant_data_keys', 'automated'),

  ('gdpr', '2016/679', 'Art-33',
   'Personal-data-breach notification (72h)',
   '72h notification to supervisory authority. Platform: incident-response runbook §Breach + dpo-notification template.',
   'manual', 'manual'),

  ('gdpr', '2016/679', 'Art-44',
   'Cross-border transfer rules',
   'Transfers to third countries require safeguards. Platform: tenants.data_region pin; multi-region overlay enforces.',
   'manual', 'semi_automated')

ON CONFLICT (framework, framework_version, control_code) DO NOTHING;

-- ----- PCI DSS 4.0 expansion ----------------------------------------
-- Add the platform-evidenced controls the previous migration missed.
INSERT INTO compliance_controls (
  framework, framework_version, control_code,
  title, description, evidence_query, automation_tier
) VALUES
  ('pci_dss', '4.0', '1.2.6',
   'Security features for insecure services and protocols',
   'Each insecure protocol used has documented justification + compensating control. Platform: scanner findings tagged by protocol.',
   'findings', 'automated'),

  ('pci_dss', '4.0', '3.5.1',
   'PAN encryption keys',
   'Strong cryptography for PAN at rest. Platform does not store PAN; if a tenant ingests it accidentally the vault still encrypts.',
   'tenant_data_keys', 'automated'),

  ('pci_dss', '4.0', '6.3.2',
   'Vulnerability inventory',
   'Inventory of bespoke + custom software components. Platform: scanner inventory + cosign-signed image digests.',
   'findings', 'automated'),

  ('pci_dss', '4.0', '7.2.5',
   'Application + system accounts least privilege',
   'Minimum privileges for accounts. Platform: RBAC + per-tenant scoping + audited mutations.',
   'audit_logs', 'automated'),

  ('pci_dss', '4.0', '8.3.6',
   'Strong authentication',
   'MFA on customer-facing access to CDE-adjacent components. Platform: MFA required for admin role; SAML/OIDC supported.',
   'audit_logs', 'automated'),

  ('pci_dss', '4.0', '10.2.1',
   'Audit log content',
   'Logs capture user, event, time, success/failure, origin. Platform: audit_logs schema + hash chain.',
   'audit_logs', 'automated'),

  ('pci_dss', '4.0', '10.5.1',
   'Audit log integrity protection',
   'Logs protected from tampering. Platform: SHA-256 hash chain + RFC 3161 TSA daily anchor.',
   'audit_archive_runs', 'automated'),

  ('pci_dss', '4.0', '12.10.1',
   'Incident response plan exists',
   'Documented incident response plan. Platform: docs/operations/incident-response.md + customer-escalation.md.',
   'manual', 'manual')

ON CONFLICT (framework, framework_version, control_code) DO NOTHING;
