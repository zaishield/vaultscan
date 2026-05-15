-- Scanner image registry: image digests the platform will execute.
-- Blueprint §12.3 ("Container image signing") requires that scanner pods only
-- ever run images whose digest is registered ahead of time. This table is the
-- authoritative allow-list. scan_tasks.image_digest is pinned at job creation
-- and verified by the scanner worker before exec.

CREATE TABLE scanner_image_registry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool            TEXT NOT NULL,
    image_ref       TEXT NOT NULL,        -- e.g. registry.zaishield.com/vaultscan/scanners/nmap:7.94
    image_digest    TEXT NOT NULL,        -- sha256:abc...  (registered after signed cosign verify)
    cosign_signature TEXT,                -- optional: base64 cosign signature manifest
    plane           TEXT NOT NULL,        -- external | internal | both
    enabled         BOOLEAN NOT NULL DEFAULT true,
    registered_by   UUID REFERENCES users(id),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tool, image_ref)
);
CREATE INDEX scanner_image_registry_tool_idx ON scanner_image_registry(tool, enabled);

-- Seed the 10 tools we ship images for. Production rotates these as new
-- versions pass the offline cosign verify pipeline.
INSERT INTO scanner_image_registry(tool, image_ref, image_digest, plane) VALUES
  ('nmap',       'registry.zaishield.com/vaultscan/scanners/nmap:7.94',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000001', 'both'),
  ('nuclei',     'registry.zaishield.com/vaultscan/scanners/nuclei:3.3',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000002', 'both'),
  ('zap',        'registry.zaishield.com/vaultscan/scanners/zap:2.15',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000003', 'both'),
  ('openvas',    'registry.zaishield.com/vaultscan/scanners/openvas:23.0',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000004', 'both'),
  ('testssl',    'registry.zaishield.com/vaultscan/scanners/testssl:3.2',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000005', 'external'),
  ('sslyze',     'registry.zaishield.com/vaultscan/scanners/sslyze:6.0',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000006', 'external'),
  ('trivy',      'registry.zaishield.com/vaultscan/scanners/trivy:0.55',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000007', 'both'),
  ('bloodhound', 'registry.zaishield.com/vaultscan/scanners/bloodhound:5.0',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000008', 'internal'),
  ('prowler',    'registry.zaishield.com/vaultscan/scanners/prowler:5.0',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000009', 'external'),
  ('kube-bench', 'registry.zaishield.com/vaultscan/scanners/kube-bench:0.9',
                  'sha256:000000000000000000000000000000000000000000000000000000000000000a', 'both'),
  ('lynis',      'registry.zaishield.com/vaultscan/scanners/lynis:3.1',
                  'sha256:000000000000000000000000000000000000000000000000000000000000000b', 'internal'),
  ('mobsf',      'registry.zaishield.com/vaultscan/scanners/mobsf:4.1',
                  'sha256:000000000000000000000000000000000000000000000000000000000000000c', 'external'),
  ('netexec',    'registry.zaishield.com/vaultscan/scanners/netexec:1.2',
                  'sha256:000000000000000000000000000000000000000000000000000000000000000d', 'internal'),
  ('katana',     'registry.zaishield.com/vaultscan/scanners/katana:1.1',
                  'sha256:000000000000000000000000000000000000000000000000000000000000000e', 'external'),
  ('ffuf',       'registry.zaishield.com/vaultscan/scanners/ffuf:2.1',
                  'sha256:000000000000000000000000000000000000000000000000000000000000000f', 'external'),
  ('amass',      'registry.zaishield.com/vaultscan/scanners/amass:4.2',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000010', 'external'),
  ('subfinder',  'registry.zaishield.com/vaultscan/scanners/subfinder:2.6',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000011', 'external'),
  ('dnsx',       'registry.zaishield.com/vaultscan/scanners/dnsx:1.2',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000012', 'external'),
  ('httpx',      'registry.zaishield.com/vaultscan/scanners/httpx:1.6',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000013', 'external'),
  ('naabu',      'registry.zaishield.com/vaultscan/scanners/naabu:2.3',
                  'sha256:0000000000000000000000000000000000000000000000000000000000000014', 'both');
