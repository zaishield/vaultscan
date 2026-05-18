-- 0060_intrusive_scan_profiles.up.sql
--
-- Adds scan profiles for the 7 scanner tools that were fully wired
-- (Dockerfile + parser + dispatch + scopeguard) but not reachable
-- via any existing profile:
--
--   dirsearch, gobuster, ffuf  — directory / file brute-forcers (high noise)
--   gitleaks                   — secret scanner (low risk; safe to add to existing devsec)
--   hydra                      — credential brute-forcer (HIGH risk; ENGAGEMENT-OPT-IN)
--   recon-ng                   — OSINT framework (low risk; passive)
--   semgrep                    — SAST (low risk; safe)
--   sqlmap                     — SQL injection exploiter (HIGH risk; ENGAGEMENT-OPT-IN)
--
-- Three new profiles:
--
--   external_web_content_discovery  → dirsearch + gobuster + ffuf
--   devsecops_sast_secrets          → semgrep + gitleaks + recon-ng
--   external_deep_pt                → hydra + sqlmap (REQUIRES APPROVAL)
--
-- The deep PT profile sets requires_approval=true so its dispatch
-- falls into the same engagement-approver flow used today for any
-- intensity=deep job. scopeguard.go's existing logic enforces this.

INSERT INTO scan_profiles(code, name, plane, intensity, description, tools, requires_approval)
VALUES
    ('external_web_content_discovery',
     'External Web Content Discovery',
     'external', 'standard',
     'Directory, file, and hidden-endpoint enumeration. Noisy — schedule outside business hours when possible.',
     '["dirsearch","gobuster","ffuf","httpx"]'::jsonb,
     false),

    ('devsecops_sast_secrets',
     'DevSecOps SAST + Secrets',
     'external', 'light',
     'Source-code static analysis + secret detection. Safe for production source trees.',
     '["semgrep","gitleaks","recon-ng"]'::jsonb,
     false),

    ('external_deep_pt',
     'External Deep PT (intrusive)',
     'external', 'deep',
     'Credential brute-force + SQL injection exploitation. ONLY for engagements with explicit written authorization for intrusive testing. Always requires per-job approval.',
     '["hydra","sqlmap","nuclei","nmap"]'::jsonb,
     true)

ON CONFLICT (code) DO UPDATE
  SET tools = EXCLUDED.tools,
      description = EXCLUDED.description,
      requires_approval = EXCLUDED.requires_approval;
