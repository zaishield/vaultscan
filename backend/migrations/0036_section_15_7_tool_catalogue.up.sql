-- §15.7 deepening: extend the scanner image registry with the 7
-- tools the original seed missed (sqlmap, gobuster, dirsearch,
-- semgrep, gitleaks, hydra, recon-ng).
--
-- All new entries are cosign-unsigned at first — operators sign them
-- via the scanner-image-release runbook before activating in
-- production. Until then RequireSignatures=false (dev) lets them
-- through with a warn; in prod they're refused.

INSERT INTO scanner_image_registry(tool, image_ref, image_digest, plane) VALUES
  ('sqlmap',    'registry.zaishield.com/vaultscan/scanners/sqlmap:1.8',
                'sha256:0000000000000000000000000000000000000000000000000000000000000020', 'external'),
  ('gobuster',  'registry.zaishield.com/vaultscan/scanners/gobuster:3.6',
                'sha256:0000000000000000000000000000000000000000000000000000000000000021', 'external'),
  ('dirsearch', 'registry.zaishield.com/vaultscan/scanners/dirsearch:0.4',
                'sha256:0000000000000000000000000000000000000000000000000000000000000022', 'external'),
  ('semgrep',   'registry.zaishield.com/vaultscan/scanners/semgrep:1.85',
                'sha256:0000000000000000000000000000000000000000000000000000000000000023', 'both'),
  ('gitleaks',  'registry.zaishield.com/vaultscan/scanners/gitleaks:8.18',
                'sha256:0000000000000000000000000000000000000000000000000000000000000024', 'both'),
  ('hydra',     'registry.zaishield.com/vaultscan/scanners/hydra:9.5',
                'sha256:0000000000000000000000000000000000000000000000000000000000000025', 'external'),
  ('recon-ng',  'registry.zaishield.com/vaultscan/scanners/recon-ng:5.1',
                'sha256:0000000000000000000000000000000000000000000000000000000000000026', 'external');
