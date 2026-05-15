-- VS-10 deepening: scheduled report runs, compliance control library,
-- PDF renderer attribution.

-- Compliance control catalog. Each row is one control in a published
-- framework (ISO 27001:2022 Annex A, PCI DSS v4.0, NIST CSF 2.0,
-- SOC 2 Type II Trust Services Criteria). Reports of type=compliance
-- map findings into these controls.
CREATE TABLE compliance_controls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework       TEXT NOT NULL,                -- iso27001 | pci_dss | nist_csf | soc2
    framework_version TEXT NOT NULL,
    control_code    TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    finding_patterns JSONB NOT NULL DEFAULT '[]', -- regexes against finding title / cwe
    UNIQUE (framework, framework_version, control_code)
);
CREATE INDEX compliance_controls_framework_idx
    ON compliance_controls(framework, framework_version);

-- Seed a small but representative set of controls per framework. Real
-- deployments load the full catalogue via a separate seeder; this gives
-- the report engine enough to generate meaningful coverage tables out
-- of the box.
INSERT INTO compliance_controls
    (framework, framework_version, control_code, title, description, finding_patterns) VALUES
  ('iso27001','2022','A.5.10','Acceptable use of information',
   'Rules for the acceptable use of information assets are documented.',
   '["data leak","exposed file","public bucket"]'),
  ('iso27001','2022','A.8.7','Protection against malware',
   'Protection against malware is implemented.',
   '["malware","ransomware","backdoor"]'),
  ('iso27001','2022','A.8.20','Network security',
   'Networks and network devices are secured.',
   '["open port","weak tls","tls 1.0","ssh weak ciphers"]'),
  ('iso27001','2022','A.8.24','Use of cryptography',
   'Cryptography is used correctly and effectively.',
   '["weak cipher","insecure hash","md5","rc4","weak certificate"]'),

  ('pci_dss','4.0','2.2.4','Insecure services disabled',
   'Insecure services, protocols, daemons, and ports are disabled.',
   '["telnet","ftp","smbv1","weak protocol"]'),
  ('pci_dss','4.0','4.2.1','Strong cryptography in transit',
   'Strong cryptography protects PAN during transmission over open public networks.',
   '["tls 1.0","tls 1.1","weak cipher","ssl3","heartbleed"]'),
  ('pci_dss','4.0','6.4.1','Public-facing web applications',
   'Public-facing web apps protected against web-based attacks.',
   '["sql injection","xss","cross-site scripting","sqli","directory traversal"]'),
  ('pci_dss','4.0','11.3.1','Internal vulnerability scans',
   'Internal vulnerability scans performed at least once every three months.',
   '["unpatched","cve-","outdated software"]'),

  ('nist_csf','2.0','ID.AM-1','Asset inventory',
   'Physical devices and systems are inventoried.',
   '["unknown asset","shadow asset","unmanaged host"]'),
  ('nist_csf','2.0','PR.AC-1','Identity management',
   'Identities and credentials are managed.',
   '["default credentials","weak password","exposed credentials"]'),
  ('nist_csf','2.0','PR.DS-2','Data in transit',
   'Data-in-transit is protected.',
   '["tls 1.0","weak cipher","mitm","sslv3"]'),
  ('nist_csf','2.0','DE.CM-8','Vulnerability scans performed',
   'Vulnerability scans are performed.',
   '["unpatched","outdated","cve-"]'),

  ('soc2','2017','CC6.1','Logical access controls',
   'Logical access security software, infrastructure, and architectures are restricted.',
   '["default credentials","weak password","exposed admin","open management"]'),
  ('soc2','2017','CC6.6','Encrypted transmission',
   'Encryption is used to protect data during transmission.',
   '["tls 1.0","weak cipher","plain http","ssl3"]'),
  ('soc2','2017','CC7.1','Vulnerability detection',
   'Detection and monitoring procedures identify changes that could introduce vulnerabilities.',
   '["unpatched","cve-","outdated software"]');

-- Report → controls mapping (which controls a report template covers).
-- Lets the UI render "this template covers 14/35 NIST controls".
CREATE TABLE report_template_compliance (
    template_id   UUID NOT NULL REFERENCES report_templates(id) ON DELETE CASCADE,
    control_id    UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    PRIMARY KEY (template_id, control_id)
);

-- Schedule definition for recurring reports.
CREATE TABLE report_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id),
    partner_id      UUID NOT NULL REFERENCES partners(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id   UUID REFERENCES engagements(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    report_type     TEXT NOT NULL,
    formats         JSONB NOT NULL DEFAULT '["pdf","html","json"]',
    cadence         TEXT NOT NULL,        -- daily | weekly | monthly | quarterly
    parameters      JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    next_run_at     TIMESTAMPTZ NOT NULL,
    last_run_at     TIMESTAMPTZ,
    last_report_id  UUID REFERENCES reports(id) ON DELETE SET NULL,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX report_schedules_due_idx
    ON report_schedules(next_run_at) WHERE enabled = true;

-- Track which renderer produced each report's PDF.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS pdf_renderer TEXT;
