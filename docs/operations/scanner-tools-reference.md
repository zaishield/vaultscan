# Scanner Tools Reference

The complete catalog of the 27 scanner tools the platform dispatches.
For each: what it does, how it's dispatched, how its findings flow
into VaultScan, what severity it can emit, what authorization it
needs, what scan profiles include it.

This is the source of truth for the "External and Internal plane"
feature surface. If something here doesn't match the code, the code
is canonical — file an issue.

## Architecture recap

```
   user submits scan
        │
        ▼
   scanorch.Submit ── validates scope + auth + residency +
        │           ── creates scan_jobs + N scan_tasks rows
        │           ── refuses if any task's image isn't pinned
        │              (strict mode in production)
        ▼
   scanner-worker (advisory-lock dequeue) ── picks queued tasks
        │
        ▼
   Kubernetes Job spawned in scanner-<tool> namespace
        │ - image:  digest-pinned via tools/scanner-images/digests.json
        │ - tool args: rendered from the scan profile
        │ - resources: per-tool CPU + memory cap
        │ - securityContext: per-tool via runner_k8s_tool_security.go
        │ - egress: locked to the engagement's approved scope
        │
        ▼
   tool runs, writes findings to stdout
        │
        ▼
   scanner-worker tails the pod, captures up to 64 MiB of output
        │
        ▼
   parsers.Lookup(tool) ── per-tool parser (see internal/parsers/)
        │                ── normalises into findings.IngestInput
        │                ── deduplicates by fingerprint
        ▼
   findings.Upsert ── writes to findings table with chain-of-custody
        │           ── publishes finding.created event
        ▼
   integration delivery + dashboard SSE + notification
```

## Per-tool catalog

For each tool: **Purpose** (what it scans for) → **Output** (what
the tool writes) → **Parser** (where it lands in the code) →
**Findings shape** (what becomes a VaultScan finding) → **Profiles**
(which scan profiles include it) → **Security** (root, hostNet,
caps).

---

### nmap
- **Purpose:** TCP / UDP port scanning, service version detection,
  OS fingerprinting, NSE script execution.
- **Output:** XML (`-oX`) — `<nmaprun>/<host>/<ports>/<port>` tree
  with state, service, script outputs.
- **Parser:** `backend/internal/parsers/parsers.go` `ParseNmap`.
- **Findings shape:** one per open port + one per NSE script hit
  (e.g. `vulners` CVEs, `http-title`, `ssl-cert`). Severity:
  high for known-CVE NSE hits; info for banner-only.
- **Profiles:** `external_discovery`, `external_standard_va`,
  `internal_discovery`, `internal_standard_va`, `external_deep_pt`.
- **Security:** non-root + `NET_RAW` (for `-sS` SYN scan, `-sU` UDP).

### nuclei
- **Purpose:** template-based vulnerability scanning (10k+ community
  templates: web CVEs, exposed admin panels, misconfigurations).
- **Output:** JSONL (`-jsonl`) — one finding per line with
  template-id, severity (template-author defined), URL, matched
  bytes.
- **Parser:** `ParseNuclei` — passes the template's severity
  through directly; CVE field maps to `cve` column.
- **Findings shape:** one finding per template hit. Severity from
  the template metadata (critical / high / medium / low / info).
- **Profiles:** `external_web`, `external_standard_va`,
  `external_deep_pt`.
- **Security:** non-root, no caps.

### trivy
- **Purpose:** container image + filesystem + IaC vulnerability
  scanning. Detects OS package CVEs, language package CVEs,
  misconfigurations (Dockerfile / k8s / Terraform), secrets.
- **Output:** JSON (`--format json`) — `Results[].Vulnerabilities[]`
  with VulnerabilityID, Severity, PkgName, FixedVersion.
- **Parser:** `ParseTrivy` — CVE per row, severity from Trivy's
  `Severity` field (UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL).
- **Findings shape:** one per (CVE, package, asset). Dedupe key
  includes target so the same CVE in two images = two findings.
- **Profiles:** `container_va`, `internal_k8s`, `devsecops_sast_secrets`.
- **Security:** non-root, no caps.

### kube-bench
- **Purpose:** CIS Kubernetes Benchmark — checks node + control-
  plane + worker configuration against the CIS guide.
- **Output:** JSON (`--json`) — `Controls[].tests[].results[]` with
  pass/fail/warn/info per check.
- **Parser:** `ParseKubeBench` — FAIL → medium/high (per check
  weight), WARN → low.
- **Findings shape:** one finding per failed/warned check.
- **Profiles:** `internal_k8s`.
- **Security:** **root + hostNetwork + hostPID** (needs to read
  /etc/kubernetes, /var/lib/kubelet, /proc/<pid> of kubelet / etcd /
  kube-apiserver).

### lynis
- **Purpose:** Linux host security audit — packages, file
  permissions, kernel hardening, authentication, services.
- **Output:** Custom text format + `.dat` summary; the wrapper
  parses both.
- **Parser:** `ParseLynis` — warnings → low; suggestions → info;
  hardening-index drop → finding with mapped severity.
- **Findings shape:** one finding per warning + a summary finding
  with the hardening index.
- **Profiles:** `internal_linux`.
- **Security:** **root** (reads /etc/shadow, /proc, /var/log/secure).
  NO hostNetwork / hostPID.

### openvas (Greenbone Community Edition)
- **Purpose:** authenticated + unauthenticated vulnerability scan
  over a wide port + protocol range. Industry-standard VA tool.
- **Output:** XML (`<report>`) per scan task.
- **Parser:** `ParseOpenVAS` — `<result>` rows → findings; severity
  from CVSS score via `severityFromCVSS`.
- **Findings shape:** one per `<result>` with cvss + cve + asset.
- **Profiles:** `external_standard_va`, `external_deep_pt`,
  `internal_standard_va`.
- **Security:** non-root + `NET_RAW` (SYN scans, ICMP).

### sslyze
- **Purpose:** TLS configuration analysis (cipher suites, cert chain,
  HSTS, OCSP stapling, downgrade-attack resistance).
- **Output:** JSON (`--json_out`).
- **Parser:** `ParseSSLyze` — flags weak ciphers, expired certs,
  TLS 1.0/1.1 enabled, RSA <2048, etc.
- **Findings shape:** one finding per (asset, weakness) — severity
  ranges low (HSTS missing) → critical (heartbleed / RC4 only).
- **Profiles:** `external_tls`.
- **Security:** non-root, no caps.

### testssl
- **Purpose:** alternative TLS scanner (different signature set
  than sslyze; runs both for coverage).
- **Output:** JSON (`--jsonfile-pretty`).
- **Parser:** `ParseTestssl` — `mapTestsslSeverity` maps testssl's
  CRITICAL / HIGH / MEDIUM / LOW / WARN / OK → VaultScan severities.
- **Profiles:** `external_tls`.
- **Security:** non-root, no caps.

### semgrep
- **Purpose:** lightweight SAST — pattern-matching across many
  languages with a community ruleset (OWASP Top 10, framework-
  specific).
- **Output:** SARIF v2.1.0 (`--sarif`).
- **Parser:** `ParseSemgrep` — `runs[].results[]` → findings with
  level → severity.
- **Findings shape:** one per rule hit, with file:line location.
- **Profiles:** `devsecops_sast_secrets`.
- **Security:** non-root, no caps.

### gitleaks
- **Purpose:** secret detection in source code, including git
  history walking.
- **Output:** JSON.
- **Parser:** `ParseGitleaks` — every leak becomes a critical
  finding (secrets in code = always high-priority).
- **Findings shape:** one per leak. Includes redacted secret
  pattern + file + commit + author.
- **Profiles:** `devsecops_sast_secrets`.
- **Security:** non-root, no caps.

### ffuf
- **Purpose:** fast web content fuzzing (directory/file/parameter
  brute-forcing).
- **Output:** JSON (`-of json`).
- **Parser:** `ParseFFUF` (in `discovery.go`) — non-404 responses
  → low/medium findings (hidden file = medium).
- **Profiles:** `external_web`, `external_web_content_discovery`.
- **Security:** non-root, no caps.

### gobuster
- **Purpose:** alternative content fuzzer; DNS subdomain + vhost
  brute-forcing on top of dir/file fuzzing.
- **Output:** plain text, structured via the wrapper.
- **Parser:** `ParseGobuster` (in `devsec.go`).
- **Profiles:** `external_web_content_discovery`.
- **Security:** non-root, no caps.

### dirsearch
- **Purpose:** Python-based directory brute-forcer (different
  wordlist + heuristics than ffuf/gobuster).
- **Output:** JSON (`--format json`).
- **Parser:** `ParseDirsearch` (in `devsec.go`).
- **Profiles:** `external_web_content_discovery`.
- **Security:** non-root, no caps.

### hydra
- **Purpose:** credential brute-force / spray (SSH / FTP /
  RDP / HTTP-form / HTTP-basic / SMB / MS-SQL / MySQL / etc.).
  **Highly intrusive.**
- **Output:** plain text — one line per success.
- **Parser:** `ParseHydra` — every success = **critical** finding
  (the credential the attacker would have).
- **Profiles:** `external_deep_pt` ONLY. The profile is gated by
  `requires_approval=true` so dispatch requires explicit engagement
  approval.
- **Security:** non-root, no caps. (The wordlist is the risk, not
  the runtime privilege.)

### sqlmap
- **Purpose:** automated SQL injection detection + (optionally)
  exploitation. Captures DBMS fingerprint, schemas, sample rows.
  **Highly intrusive.**
- **Output:** custom XML + console log; wrapper extracts the
  vulnerable parameters.
- **Parser:** `ParseSQLmap` (in `devsec.go`) — every confirmed
  injection = **critical** finding.
- **Profiles:** `external_deep_pt` ONLY (requires_approval=true).
- **Security:** non-root, no caps.

### mobsf (Mobile Security Framework)
- **Purpose:** static + dynamic analysis of Android APK / iOS IPA
  binaries. Detects insecure crypto, insecure permissions, embedded
  secrets, OWASP MASVS violations.
- **Output:** JSON via the MobSF REST API (the wrapper invokes it).
- **Parser:** `ParseMobSF` — findings mapped to severity from
  MobSF's risk score.
- **Profiles:** `mobile_static`.
- **Security:** non-root, no caps.

### zap (OWASP Zed Attack Proxy)
- **Purpose:** web application scanner — active scan with payload
  injection, passive scan via spidered traffic. Industry standard
  for DAST.
- **Output:** JSON (`-jsonReport`).
- **Parser:** `ParseZAP` — `alerts[]` → findings with `riskcode`
  3/2/1/0 → high/medium/low/info.
- **Profiles:** `external_web`, `internal_web`.
- **Security:** non-root, no caps.

### prowler
- **Purpose:** cloud-posture (CSPM) for AWS / Azure / GCP / Kubernetes.
  Runs hundreds of CIS / SOC2 / PCI checks against the live cloud API.
- **Output:** JSON-OCSF.
- **Parser:** `ParseProwler` — failed checks → findings; severity
  from Prowler's severity tag.
- **Findings shape:** one per failed check with cloud resource ID.
- **Profiles:** `cloud_posture`.
- **Security:** non-root, no caps. (Credentials in env via
  Kubernetes Secret.)

### recon-ng
- **Purpose:** OSINT framework — pivot through reconnaissance
  modules to enrich a target (whois, certificate transparency, etc.).
- **Output:** JSON via the module's `--output json`.
- **Parser:** `ParseReconNg` (in `devsec.go`) — emits info-severity
  findings for discovered hosts / emails / certs.
- **Profiles:** `devsecops_sast_secrets`. (Despite the name, recon-
  ng's role here is passive enrichment.)
- **Security:** non-root, no caps.

### naabu
- **Purpose:** fast SYN port scanner (ProjectDiscovery — same
  authors as nuclei + subfinder).
- **Output:** JSONL (`-json`).
- **Parser:** `ParseNaabu` (in `discovery.go`) — one finding per
  open port (low / info).
- **Profiles:** `external_discovery`.
- **Security:** non-root + `NET_RAW`.

### dnsx
- **Purpose:** DNS resolution toolkit — wildcard detection,
  brute-forcing, takeover candidate detection.
- **Output:** JSONL.
- **Parser:** `ParseDNSX` (in `discovery.go`) — info findings for
  resolved hosts; high for subdomain-takeover candidates.
- **Profiles:** `external_discovery`.
- **Security:** non-root, no caps.

### subfinder
- **Purpose:** passive subdomain enumeration (queries 30+ data
  sources: CT logs, search engines, threat-intel APIs).
- **Output:** JSONL.
- **Parser:** `ParseSubfinder` (in `discovery.go`) — info finding
  per discovered subdomain.
- **Profiles:** `external_discovery`.
- **Security:** non-root, no caps.

### amass
- **Purpose:** subdomain enumeration + relationship mapping (active
  + passive). OWASP project.
- **Output:** JSONL (`-json`).
- **Parser:** `ParseAmass` (in `discovery.go`) — info findings.
- **Profiles:** `external_discovery`.
- **Security:** non-root, no caps.

### bloodhound (collector)
- **Purpose:** Active Directory attack-path mapping. Collects AD
  objects + ACLs + group memberships; the analysis runs in the
  BloodHound UI / SDK.
- **Output:** JSON (collector zip; unpacked by the wrapper).
- **Parser:** `ParseBloodhound` — high findings for
  Kerberoastable / ASREP-roastable accounts, Domain Admin path
  candidates.
- **Profiles:** `internal_ad`.
- **Security:** non-root. Requires AD credentials (via Secret).

### httpx
- **Purpose:** HTTP probing — multi-purpose: detects live web
  servers, fingerprints tech stack, captures titles + status codes.
- **Output:** JSONL.
- **Parser:** `ParseHTTPX` (in `discovery.go`) — info findings for
  alive hosts; medium when a tech fingerprint matches a known-CVE
  rule.
- **Profiles:** `external_discovery`, `external_web`,
  `external_tls`, `external_web_content_discovery`.
- **Security:** non-root, no caps.

### katana
- **Purpose:** headless-browser crawler — builds a sitemap of
  discoverable URLs (JS-rendered apps too).
- **Output:** JSONL.
- **Parser:** `ParseKatana` (in `discovery.go`) — info findings
  per discovered endpoint; medium when an endpoint matches an
  exposure rule.
- **Profiles:** `external_web`.
- **Security:** non-root, no caps. Headless Chromium bundled.

### netexec (formerly CrackMapExec)
- **Purpose:** post-exploitation toolkit for SMB / WinRM / MSSQL /
  LDAP / RDP. Tests SMB signing, enumerates shares, sprays creds.
- **Output:** JSON via `--jsonfile`.
- **Parser:** `ParseNetExec` — findings for weak SMB config,
  exposed shares, valid creds (when authenticated mode is used).
- **Profiles:** `internal_ad`.
- **Security:** non-root, no caps. Requires AD creds.

---

## Severity normalisation

Every parser maps tool-specific severity into VaultScan's 5-level
scheme:

| VaultScan | Definition |
| --- | --- |
| critical | Compromise of the asset is trivially achievable, OR data is already exposed |
| high     | Compromise is straightforward (known exploit + matching version), OR a chain of mediums |
| medium   | Defense-in-depth weakness; not directly exploitable but raises blast radius |
| low      | Information-disclosure or hardening miss; opportunistic value |
| info     | Discovered fact; not a vulnerability (e.g. "this subdomain exists") |

`severityFromCVSS` is the default mapping when a tool emits CVSS:
- 9.0+  → critical
- 7.0–8.9 → high
- 4.0–6.9 → medium
- 0.1–3.9 → low
- 0     → info

## Authorization enforcement

EVERY scan submission goes through `scopeguard.Decide`:

1. The engagement must be `status='active'` AND not paused
2. An authorization document must be on file for the engagement
3. The target (domain / IP / cloud account) must be in
   `scope_targets` for the engagement with `status='approved'`
4. The intensity must be ≤ what the engagement permits (deep
   requires a separate approval per scan)
5. For internal-plane scans, the dispatching agent must be in
   `agent_assigned_scope` for the engagement
6. The per-tenant + per-engagement rate limit must allow it
7. The current time must be in the engagement's allowed window
   (some engagements restrict scans to business hours)

Decision logged to `scope_decision_logs`. Refused scans NEVER enter
the task queue.

## End-to-end testing

The scanner pipeline has dedicated integration tests:

| Test | What it asserts |
| --- | --- |
| `backend/test/integration/scanner_test.go` `TestScannerWorker_EndToEnd` | submitted job → synthetic nmap output → parser → findings table |
| `backend/test/integration/scanner_coverage_test.go` `TestSCANNERS_EveryRegisteredToolHasDockerfile` | every registered tool has a Dockerfile |
| `backend/test/integration/scanner_coverage_test.go` `TestSCANNERS_EveryRegisteredToolHasParser` | every registered tool has a parser registered in `parsers.Registry` |
| `backend/internal/scanner/runner_k8s_tool_security_test.go` | per-tool security context (kube-bench/lynis = root; nmap/openvas/naabu = NET_RAW; etc.) |
| `backend/internal/parsers/fuzz_test.go` | fuzz harnesses against parsers (nmap, nuclei, trivy, etc.) |

Adding a new tool without a Dockerfile + parser will fail
`scanner_coverage_test.go` — the build won't merge.

## Adding a new tool

See `docs/operations/role-guides/developer.md` §"How to add a new
scanner tool" for the end-to-end procedure.
