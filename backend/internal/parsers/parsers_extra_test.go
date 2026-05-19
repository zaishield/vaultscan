// parsers_extra_test.go — coverage adds for ParseOpenVAS, ParseTrivy,
// ParseProwler, ParseKubeBench, ParseLynis, ParseSslyze, ParseNetexec,
// ParseMobSF. Each test exercises a minimal real-tool fixture and
// asserts both the happy path (findings produced) and the most
// common edge cases (empty input, malformed JSON/XML).
package parsers

import (
	"testing"
)

// ----- OpenVAS XML --------------------------------------------------------

func TestParseOpenVAS_BasicXML(t *testing.T) {
	t.Parallel()
	raw := []byte(`<?xml version="1.0"?>
<report>
  <results>
    <result>
      <name>Apache HTTP server outdated</name>
      <description>Apache 2.4.49 is vulnerable to CVE-2021-41773.</description>
      <severity>9.8</severity>
      <host>10.0.0.5</host>
      <port>443/tcp</port>
      <nvt><cve>CVE-2021-41773</cve></nvt>
    </result>
    <result>
      <name>Self-signed certificate</name>
      <description>SSL cert is self-signed.</description>
      <severity>3.7</severity>
      <host>10.0.0.5</host>
      <port>443/tcp</port>
      <nvt><cve>NOCVE</cve></nvt>
    </result>
  </results>
</report>`)
	out, err := ParseOpenVAS(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].Severity != "critical" {
		t.Errorf("CVSS 9.8 should map to critical, got %q", out[0].Severity)
	}
	if out[0].CVE != "CVE-2021-41773" {
		t.Errorf("expected CVE-2021-41773, got %q", out[0].CVE)
	}
	if out[0].Port != 443 || out[0].Protocol != "tcp" {
		t.Errorf("expected 443/tcp, got %d/%s", out[0].Port, out[0].Protocol)
	}
	if out[1].CVE != "" {
		t.Errorf("NOCVE marker should be scrubbed, got %q", out[1].CVE)
	}
}

func TestParseOpenVAS_MalformedXML(t *testing.T) {
	t.Parallel()
	if _, err := ParseOpenVAS(Context{}, []byte("<not-xml")); err == nil {
		t.Error("expected error on malformed XML")
	}
}

// ----- Trivy JSON --------------------------------------------------------

func TestParseTrivy_ContainerVulns(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "ArtifactName": "nginx:1.21.0",
  "Results": [
    {
      "Target": "nginx:1.21.0 (debian 11.3)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2022-23308",
          "PkgName": "libxml2",
          "InstalledVersion": "2.9.10-1",
          "Severity": "HIGH",
          "Title": "libxml2 use-after-free",
          "Description": "A use-after-free in libxml2 ...",
          "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
          "References": ["https://nvd.nist.gov/vuln/detail/CVE-2022-23308"],
          "CweIDs": ["CWE-416"]
        }
      ]
    }
  ]
}`)
	out, err := ParseTrivy(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.CVE != "CVE-2022-23308" {
		t.Errorf("CVE %q", f.CVE)
	}
	if f.Severity != "high" {
		t.Errorf("severity %q (expected lowercased)", f.Severity)
	}
	if f.CVSSScore != 7.5 {
		t.Errorf("score %f", f.CVSSScore)
	}
	if f.CWE != "CWE-416" {
		t.Errorf("cwe %q", f.CWE)
	}
}

func TestParseTrivy_NoResults(t *testing.T) {
	t.Parallel()
	out, err := ParseTrivy(Context{}, []byte(`{"Results":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 findings, got %d", len(out))
	}
}

// ----- Prowler OCSF JSON -------------------------------------------------

func TestParseProwler_OnlyFailures(t *testing.T) {
	t.Parallel()
	raw := []byte(`[
  {
    "status": "PASS",
    "severity": "medium",
    "region": "us-east-1",
    "check_title": "S3 bucket public read",
    "check_id": "S3.1",
    "resource": {"id": "my-bucket", "arn": "arn:aws:s3:::my-bucket"},
    "description": "Pass — bucket not public"
  },
  {
    "status": "FAIL",
    "severity": "high",
    "region": "us-east-1",
    "check_title": "RDS unencrypted",
    "check_id": "RDS.4",
    "resource": {"id": "prod-db", "arn": "arn:aws:rds:::prod-db"},
    "description": "RDS instance has storage_encrypted=false"
  }
]`)
	out, err := ParseProwler(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding (PASS filtered out), got %d", len(out))
	}
	if out[0].Severity != "high" {
		t.Errorf("severity %q", out[0].Severity)
	}
}

// ----- KubeBench JSON ----------------------------------------------------

func TestParseKubeBench_FailMapsToHigh(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "tests": [
    {
      "results": [
        {"test_number": "1.2.5", "test_desc": "Ensure --kubelet-https is on", "status": "PASS"},
        {"test_number": "1.2.6", "test_desc": "Ensure --kubelet-certificate-authority", "status": "FAIL", "remediation": "Set --kubelet-certificate-authority"},
        {"test_number": "1.2.7", "test_desc": "Ensure --authorization-mode", "status": "WARN", "remediation": "Set --authorization-mode=Webhook"}
      ]
    }
  ]
}`)
	out, err := ParseKubeBench(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (PASS filtered), got %d", len(out))
	}
	// FAIL → high, WARN → medium
	sev := map[string]string{}
	for _, f := range out {
		sev[f.Title] = f.Severity
	}
	if sev["CIS 1.2.6: Ensure --kubelet-certificate-authority"] != "high" {
		t.Errorf("FAIL should map to high, got %v", sev)
	}
	if sev["CIS 1.2.7: Ensure --authorization-mode"] != "medium" {
		t.Errorf("WARN should map to medium, got %v", sev)
	}
}

// ----- Lynis text --------------------------------------------------------

func TestParseLynis_WarningsAndSuggestions(t *testing.T) {
	t.Parallel()
	raw := []byte(`# lynis report
warning[]=WEAK_PERM|/etc/shadow not 600|-|-|
suggestion[]=AUTH-9230|Set up password aging|-|-|
ignored: not-a-warning
warning[]=SSH-7408|Permit root login enabled|-|-|
`)
	out, err := ParseLynis(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 findings (2 warning, 1 suggestion), got %d", len(out))
	}
	severities := map[string]int{}
	for _, f := range out {
		severities[f.Severity]++
	}
	if severities["medium"] != 2 || severities["low"] != 1 {
		t.Errorf("expected 2 medium + 1 low, got %v", severities)
	}
}

// ----- SSLyze JSON -------------------------------------------------------

func TestParseSslyze_ServerScanResults(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "server_scan_results": [
    {"server_location": {"hostname": "example.com", "port": 443}},
    {"server_location": {"hostname": "api.example.com", "port": 443}}
  ]
}`)
	out, err := ParseSslyze(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].Scanner != "sslyze" {
		t.Errorf("scanner %q", out[0].Scanner)
	}
}

// ----- NetExec text ------------------------------------------------------

func TestParseNetexec_VulnerableLines(t *testing.T) {
	t.Parallel()
	raw := []byte(`SMB         10.0.0.5      445    DC01             [+] Discovered
SMB         10.0.0.5      445    DC01             [!] VULNERABLE: MS17-010 (EternalBlue)
SMB         10.0.0.6      445    WS01             [-] No vulnerabilities
SMB         10.0.0.7      445    WS02             VulNeRable to Zerologon
`)
	out, err := ParseNetexec(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (2 'vulnerable' lines), got %d", len(out))
	}
	for _, f := range out {
		if f.Severity != "high" {
			t.Errorf("severity %q", f.Severity)
		}
	}
}

// ----- MobSF JSON --------------------------------------------------------

func TestParseMobSF_FindingsList(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "findings": [
    {"severity": "high", "title": "Hardcoded API key", "description": "AKIA... in res/values/strings.xml"},
    {"severity": "medium", "title": "Cleartext traffic permitted", "description": "android:usesCleartextTraffic=true"}
  ]
}`)
	out, err := ParseMobSF(Context{}, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].Title != "MobSF: Hardcoded API key" {
		t.Errorf("title %q", out[0].Title)
	}
	if out[0].Severity != "high" || out[1].Severity != "medium" {
		t.Errorf("severities %s / %s", out[0].Severity, out[1].Severity)
	}
}
