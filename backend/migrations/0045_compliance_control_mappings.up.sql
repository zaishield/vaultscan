-- 0045 — Concrete control mapping for SOC 2 / ISO 27001 / PCI-DSS /
-- HIPAA. Closes SEV-3.7 from the forensic report: the §22 compliance
-- dashboard rendered generic finding severity counts; auditors got a
-- number, not a control walk-through.
--
-- Two tables:
--
--   compliance_controls    canonical catalog of every control we map.
--                          One row per (framework, control_code). Seeded
--                          via INSERTs below for the four frameworks.
--
--   compliance_evidence    runtime evidence we collect for each
--                          control: a query reference, the most recent
--                          observation count, a verdict (pass/fail/
--                          manual), and a free-text note. The
--                          analytics worker refreshes this table on a
--                          schedule.
--
-- The seed below ships the actual control mappings — what scan
-- profile, retention policy, RBAC rule, or audit query satisfies
-- which control. Auditors get a clickable walk-through; ops get
-- a single source of truth for "which finding queries support our
-- SOC 2 CC6.1 attestation".

BEGIN;

CREATE TABLE compliance_controls (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework          TEXT NOT NULL,           -- soc2 | iso27001 | pci_dss | hipaa
    framework_version  TEXT NOT NULL,
    control_code       TEXT NOT NULL,           -- CC6.1, A.5.1, 8.2, 164.312(a)(1)
    title              TEXT NOT NULL,
    description        TEXT,
    -- evidence_query is a logical reference to the SQL / metric the
    -- analytics worker runs to satisfy this control. NULL = manual.
    --
    -- Conventions:
    --   findings:severity=high,age<30d
    --   audit_logs:event=EvidenceDownloaded,actor_type=user,window=90d
    --   scan_jobs:status=succeeded,window=7d
    --   retention:event_prefix=evidence,retention_days>=2555
    --   manual:reviewer-attests
    evidence_query     TEXT,
    automation_tier    TEXT NOT NULL,           -- automated | semi_automated | manual
    UNIQUE (framework, framework_version, control_code)
);

CREATE INDEX compliance_controls_framework_idx
    ON compliance_controls(framework, framework_version);

CREATE TABLE compliance_evidence (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    control_id         UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    -- Verdict: pass | fail | manual | n/a
    verdict            TEXT NOT NULL,
    -- observed_count is the row count from the query (when
    -- applicable). The dashboard renders this as "12 critical findings
    -- aged >90d → control fails".
    observed_count     BIGINT,
    -- Free-text note from the analytics worker OR the human reviewer
    -- (when automation_tier=manual).
    note               TEXT,
    observed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewer_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (tenant_id, control_id, observed_at)
);

CREATE INDEX compliance_evidence_latest_idx
    ON compliance_evidence(tenant_id, control_id, observed_at DESC);

ALTER TABLE compliance_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence FORCE  ROW LEVEL SECURITY;
CREATE POLICY compliance_evidence_tenant_isolation ON compliance_evidence
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());

-- ---- Seed: SOC 2 Trust Services Criteria (2017, revised 2022) -----------
INSERT INTO compliance_controls(framework, framework_version, control_code,
    title, description, evidence_query, automation_tier) VALUES
  ('soc2', '2022', 'CC6.1', 'Logical access controls restrict access',
   'The entity implements logical access security software, infrastructure, and architectures over protected information assets.',
   'audit_logs:event=UserAuthSucceeded,actor_type=user,window=30d', 'automated'),
  ('soc2', '2022', 'CC6.2', 'New internal/external user identification',
   'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.',
   'audit_logs:event=UserCreated,window=90d', 'automated'),
  ('soc2', '2022', 'CC6.6', 'Logical access removal on termination',
   'The entity removes the credentials of users whose access is no longer authorized.',
   'audit_logs:event=UserDeactivated,window=90d', 'automated'),
  ('soc2', '2022', 'CC6.7', 'Restrict and monitor remote access',
   'The entity restricts the transmission, movement, and removal of information to authorized internal and external users.',
   'integrations:type=siem,enabled=true', 'automated'),
  ('soc2', '2022', 'CC7.1', 'Detection of system configuration changes',
   'To meet objectives, the entity uses detection and monitoring procedures to identify changes to configurations.',
   'audit_logs:event_prefix=Config,window=30d', 'automated'),
  ('soc2', '2022', 'CC7.2', 'System monitoring + anomaly detection',
   'The entity monitors system components and the operation of those components for anomalies.',
   'findings:severity>=high,age<30d', 'automated'),
  ('soc2', '2022', 'CC7.3', 'Evaluation of security incidents',
   'The entity evaluates security events to determine whether they could or have resulted in a failure.',
   'audit_logs:event=EmergencyStopTriggered,window=90d', 'automated'),
  ('soc2', '2022', 'CC8.1', 'Change management',
   'The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.',
   'audit_logs:event_prefix=ScanProfile,window=90d', 'automated'),
  ('soc2', '2022', 'A1.2', 'Environmental protections + backups',
   'The entity authorizes, designs, develops, configures, documents, tests, approves, and implements environmental protections, including backups.',
   'manual:reviewer-attests-restore-verify-passing', 'semi_automated'),
  ('soc2', '2022', 'C1.1', 'Confidentiality information protected',
   'The entity identifies and maintains confidential information to meet the entity''s objectives related to confidentiality.',
   'evidence:encrypted=true,worm_enabled=true', 'automated'),
  ('soc2', '2022', 'P3.1', 'Personal information collected for purpose',
   'Personal information is collected consistent with the entity''s objectives related to privacy.',
   'manual:reviewer-attests-privacy-notice', 'manual'),
  ('soc2', '2022', 'PI1.1', 'Processing integrity',
   'The entity obtains or generates, uses, and communicates relevant, quality information regarding processing.',
   'audit_logs:chain_integrity=true,window=24h', 'automated');

-- ---- Seed: ISO/IEC 27001:2022 (Annex A controls) ------------------------
INSERT INTO compliance_controls(framework, framework_version, control_code,
    title, description, evidence_query, automation_tier) VALUES
  ('iso27001', '2022', 'A.5.1', 'Information security policies',
   'Defined, approved, published, communicated, acknowledged.',
   'manual:reviewer-attests-policy-published', 'manual'),
  ('iso27001', '2022', 'A.5.7', 'Threat intelligence',
   'Information relating to information security threats shall be collected and analysed.',
   'integrations:type=siem,enabled=true', 'automated'),
  ('iso27001', '2022', 'A.5.15', 'Access control',
   'Rules to control physical and logical access shall be established.',
   'audit_logs:event=UserAuthSucceeded,window=30d', 'automated'),
  ('iso27001', '2022', 'A.5.23', 'Information security for use of cloud services',
   'Processes for acquisition, use, management and exit from cloud services.',
   'cloud_posture:provider=aws,verdict=pass,window=7d', 'automated'),
  ('iso27001', '2022', 'A.5.24', 'Information security incident management planning',
   'Plan and prepare for managing information security incidents.',
   'audit_logs:event=EmergencyStopTriggered,window=90d', 'automated'),
  ('iso27001', '2022', 'A.5.30', 'ICT readiness for business continuity',
   'ICT readiness shall be planned, implemented, maintained and tested based on business continuity objectives.',
   'audit_archive_runs:tsa_token IS NOT NULL,window=30d', 'automated'),
  ('iso27001', '2022', 'A.8.7', 'Protection against malware',
   'Combination of user awareness and protection against malware.',
   'scan_jobs:profile_code=ext_recon_quick,status=succeeded,window=7d', 'automated'),
  ('iso27001', '2022', 'A.8.8', 'Management of technical vulnerabilities',
   'Vulnerabilities shall be obtained, evaluated, addressed.',
   'findings:status=open,severity>=high,age>30d', 'automated'),
  ('iso27001', '2022', 'A.8.12', 'Data leakage prevention',
   'Data leakage prevention measures shall be applied.',
   'evidence:encrypted=true', 'automated'),
  ('iso27001', '2022', 'A.8.15', 'Logging',
   'Logs that record activities, exceptions, faults and other relevant events shall be produced.',
   'audit_logs:chain_integrity=true,window=24h', 'automated'),
  ('iso27001', '2022', 'A.8.16', 'Monitoring activities',
   'Networks, systems and applications shall be monitored for anomalous behaviour.',
   'findings:severity>=high,window=7d', 'automated'),
  ('iso27001', '2022', 'A.8.24', 'Use of cryptography',
   'Rules for the effective use of cryptography, including cryptographic key management.',
   'tenant_data_keys:kek_version>0', 'automated');

-- ---- Seed: PCI-DSS v4.0 -------------------------------------------------
INSERT INTO compliance_controls(framework, framework_version, control_code,
    title, description, evidence_query, automation_tier) VALUES
  ('pci_dss', '4.0', '1.2.1', 'Network security controls configured',
   'Configuration standards for network security controls.',
   'cloud_posture:control=CIS-AWS-5.2,verdict=pass', 'automated'),
  ('pci_dss', '4.0', '2.2.1', 'Configuration standards developed',
   'Configuration standards address all known vulnerabilities consistent with industry standards.',
   'findings:scanner=lynis,severity>=high', 'automated'),
  ('pci_dss', '4.0', '3.5.1', 'PAN unreadable wherever stored',
   'PAN is rendered unreadable wherever it is stored.',
   'evidence:encrypted=true', 'automated'),
  ('pci_dss', '4.0', '6.3.1', 'Security vulnerabilities identified',
   'Security vulnerabilities are identified and managed.',
   'findings:status=open,cve_score>=7.0', 'automated'),
  ('pci_dss', '4.0', '6.3.3', 'All system components protected from known vulnerabilities',
   'Critical or high-security patches/updates are installed within one month of release.',
   'findings:severity=critical,age>30d', 'automated'),
  ('pci_dss', '4.0', '10.2.1', 'Audit logs enabled and active',
   'Audit logs are enabled for all system components.',
   'audit_logs:rows_inserted_per_day>0,window=7d', 'automated'),
  ('pci_dss', '4.0', '10.3.2', 'Audit log files protected',
   'Audit log files are protected to prevent modifications.',
   'audit_logs:chain_integrity=true,window=24h', 'automated'),
  ('pci_dss', '4.0', '10.4.1', 'Audit logs reviewed daily',
   'Critical-system audit log reviews performed daily.',
   'audit_tsa_anchors:window=24h', 'automated'),
  ('pci_dss', '4.0', '10.5.1', 'Audit log retention ≥ 1 year',
   '12 months retention, 3 months immediately available.',
   'retention:event_prefix=*,retention_days>=365', 'automated'),
  ('pci_dss', '4.0', '11.3.1', 'Internal vulnerability scans quarterly',
   'Internal vulnerability scans are performed at least once every three months.',
   'scan_jobs:plane=internal,status=succeeded,window=90d', 'automated'),
  ('pci_dss', '4.0', '11.4.1', 'External + ASV scans quarterly',
   'External vulnerability scans by an ASV every three months.',
   'scan_jobs:plane=external,status=succeeded,window=90d', 'automated'),
  ('pci_dss', '4.0', '12.10.1', 'Incident response plan exists',
   'Incident response plan exists, ready to be implemented.',
   'manual:reviewer-attests-ir-plan-current', 'manual');

-- ---- Seed: HIPAA Security Rule (45 CFR 164.30x) -------------------------
INSERT INTO compliance_controls(framework, framework_version, control_code,
    title, description, evidence_query, automation_tier) VALUES
  ('hipaa', 'sec-rule-2013', '164.308(a)(1)(ii)(A)', 'Risk analysis',
   'Conduct an accurate and thorough assessment of the potential risks and vulnerabilities.',
   'findings:status=open,window=90d', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.308(a)(1)(ii)(B)', 'Risk management',
   'Implement security measures sufficient to reduce risks and vulnerabilities.',
   'findings:status=resolved,window=90d', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.308(a)(5)(ii)(B)', 'Protection from malicious software',
   'Procedures for guarding against, detecting, and reporting malicious software.',
   'scan_jobs:status=succeeded,window=7d', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.308(a)(6)(ii)', 'Response and reporting',
   'Identify and respond to suspected or known security incidents.',
   'audit_logs:event=EmergencyStopTriggered,window=90d', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.310(b)', 'Workstation use',
   'Implement policies and procedures that specify the proper functions to be performed.',
   'manual:reviewer-attests-workstation-policy', 'manual'),
  ('hipaa', 'sec-rule-2013', '164.312(a)(1)', 'Access control',
   'Implement technical policies and procedures for electronic information systems that maintain ePHI.',
   'audit_logs:event=UserAuthSucceeded,window=30d', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.312(a)(2)(iv)', 'Encryption and decryption',
   'Implement a mechanism to encrypt and decrypt electronic protected health information.',
   'evidence:encrypted=true', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.312(b)', 'Audit controls',
   'Implement hardware, software, and/or procedural mechanisms that record and examine activity.',
   'audit_logs:chain_integrity=true,window=24h', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.312(c)(1)', 'Integrity',
   'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
   'evidence:worm_enabled=true', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.312(d)', 'Person or entity authentication',
   'Implement procedures to verify that a person or entity seeking access is the one claimed.',
   'audit_logs:event=MFAVerified,window=30d', 'automated'),
  ('hipaa', 'sec-rule-2013', '164.312(e)(1)', 'Transmission security',
   'Implement technical security measures to guard against unauthorized access to ePHI transmitted.',
   'manual:reviewer-attests-tls-only', 'semi_automated'),
  ('hipaa', 'sec-rule-2013', '164.316(b)(2)(i)', 'Retention',
   'Retain documentation required for 6 years from the date of its creation.',
   'retention:event_prefix=*,retention_days>=2190', 'automated');

COMMIT;
