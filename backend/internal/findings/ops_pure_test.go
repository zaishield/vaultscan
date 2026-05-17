package findings

import (
	"strings"
	"testing"
)

// ClusterKey is the dedup fingerprint that groups "same family"
// findings. Tested heavily because finding-count metrics, SLA
// timers, and remediation tickets all key off this — a regression
// here cascades into compliance reports.

func TestClusterKey_StripsPortDifferences(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "nmap", Title: "TLS 1.0 enabled on tcp/443"})
	b := ClusterKey(IngestInput{Scanner: "nmap", Title: "TLS 1.0 enabled on tcp/8443"})
	if a != b {
		t.Errorf("port should be stripped — got distinct keys %q / %q", a, b)
	}
}

func TestClusterKey_StripsIPDifferences(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "nuclei", Title: "SSRF on 10.0.0.1"})
	b := ClusterKey(IngestInput{Scanner: "nuclei", Title: "SSRF on 192.168.7.42"})
	if a != b {
		t.Errorf("IP should be stripped — got distinct keys")
	}
}

func TestClusterKey_StripsHostnameDifferences(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "zap", Title: "XSS reflected on foo.example.com"})
	b := ClusterKey(IngestInput{Scanner: "zap", Title: "XSS reflected on bar.example.com"})
	if a != b {
		t.Errorf("hostname should be stripped")
	}
}

func TestClusterKey_StripsUUID(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "trivy", Title: "CVE-2024-1234 in image 11111111-1111-1111-1111-111111111111"})
	b := ClusterKey(IngestInput{Scanner: "trivy", Title: "CVE-2024-1234 in image 22222222-2222-2222-2222-222222222222"})
	if a != b {
		t.Errorf("UUID should be stripped")
	}
}

func TestClusterKey_DifferentScannersHaveDifferentKeys(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "nmap", Title: "TLS 1.0 enabled"})
	b := ClusterKey(IngestInput{Scanner: "nuclei", Title: "TLS 1.0 enabled"})
	if a == b {
		t.Errorf("different scanners must produce different keys; both = %q", a)
	}
}

func TestClusterKey_DifferentCVEsHaveDifferentKeys(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "trivy", CVE: "CVE-2024-1234", Title: "vuln in libxml2"})
	b := ClusterKey(IngestInput{Scanner: "trivy", CVE: "CVE-2024-5678", Title: "vuln in libxml2"})
	if a == b {
		t.Errorf("different CVEs must produce different keys; both = %q", a)
	}
}

// CVE case-insensitivity: "cve-2024-1234" and "CVE-2024-1234" must
// cluster together (the helper ToUppers the CVE).
func TestClusterKey_CVECaseInsensitive(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "x", CVE: "cve-2024-1", Title: "y"})
	b := ClusterKey(IngestInput{Scanner: "x", CVE: "CVE-2024-1", Title: "y"})
	if a != b {
		t.Errorf("CVE case should be normalised — got %q vs %q", a, b)
	}
}

func TestClusterKey_TitleCaseInsensitive(t *testing.T) {
	t.Parallel()
	a := ClusterKey(IngestInput{Scanner: "x", Title: "Generic XSS"})
	b := ClusterKey(IngestInput{Scanner: "x", Title: "generic xss"})
	if a != b {
		t.Errorf("title case should be normalised")
	}
}

// stripVariableTokens is the helper that does the actual scrubbing.
// Direct test so regressions in regexp are caught.
func TestStripVariableTokens_PortPattern(t *testing.T) {
	t.Parallel()
	got := stripVariableTokens("vuln on tcp/443 detected")
	if !strings.Contains(got, "#PORT") {
		t.Errorf("port not replaced: %q", got)
	}
	if strings.Contains(got, "443") {
		t.Errorf("port number still present: %q", got)
	}
}

func TestStripVariableTokens_CollapsesWhitespace(t *testing.T) {
	t.Parallel()
	got := stripVariableTokens("a   b  c")
	if got != "a b c" {
		t.Errorf("whitespace not collapsed: %q", got)
	}
}

// severityRank ordering — used by the severity-override path.
// Critical > High > Medium > Low > Info; unknown = 0.
func TestSeverityRank_Ordering(t *testing.T) {
	t.Parallel()
	if severityRank("critical") <= severityRank("high") {
		t.Error("critical must outrank high")
	}
	if severityRank("high") <= severityRank("medium") {
		t.Error("high must outrank medium")
	}
	if severityRank("medium") <= severityRank("low") {
		t.Error("medium must outrank low")
	}
	if severityRank("low") <= severityRank("info") {
		t.Error("low must outrank info")
	}
	if severityRank("unknown-severity") != 0 {
		t.Errorf("unknown severity should rank 0, got %d", severityRank("unknown-severity"))
	}
}

func TestSeverityRank_CaseInsensitive(t *testing.T) {
	t.Parallel()
	if severityRank("CRITICAL") != severityRank("critical") {
		t.Error("severity rank should be case-insensitive")
	}
}

// matchesCaseInsensitive: the regex helper used by AddSuppressionRule
// + AddSeverityOverride. Empty pattern = match-anything; invalid
// pattern = no match.
func TestMatchesCaseInsensitive(t *testing.T) {
	t.Parallel()
	if !matchesCaseInsensitive("", "anything") {
		t.Error("empty pattern should match anything")
	}
	if !matchesCaseInsensitive("TLS", "tls 1.0 enabled") {
		t.Error("expected case-insensitive prefix to match")
	}
	if matchesCaseInsensitive("OPENSSL", "TLS 1.0 enabled") {
		t.Error("pattern not present in target — should not match")
	}
	// Invalid regex must not panic AND must return false.
	if matchesCaseInsensitive("[invalid", "anything") {
		t.Error("invalid regex should return false (no match)")
	}
}
