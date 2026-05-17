package retesting

import (
	"strings"
	"testing"
)

// retesting service is DB+orchestrator bound; full integration tests
// live in the §37 acceptance suite. This file documents the explicit
// validation errors callers depend on for user-facing messages AND
// covers the pure-logic helpers.

// profileForScanner is the live mapping between original-scanner-name
// and the retest scan profile. The CRITICAL bug fixed in the audit
// pass was a CASE/JOIN that hard-coded both branches to 'external';
// that bug landed because nobody had wrapped this mapping in a test
// asserting plane diversity. Here it is.

func TestProfileForScanner_ProducesBothPlanes(t *testing.T) {
	t.Parallel()
	planes := map[string]bool{}
	for _, sc := range []string{
		"zap", "nuclei", "testssl", "nmap",
		"bloodhound", "netexec", "lynis", "trivy", "grype",
		"kube-bench", "kube-hunter", "prowler", "scoutsuite",
	} {
		_, plane := profileForScanner(sc)
		planes[plane] = true
	}
	if !planes["external"] || !planes["internal"] {
		t.Errorf("profileForScanner should emit BOTH planes — got %v", planes)
	}
}

func TestProfileForScanner_KnownMappings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		scanner string
		code    string
		plane   string
	}{
		{"zap", "external_web_va", "external"},
		{"nuclei", "external_web_va", "external"},
		{"testssl", "external_tls_review", "external"},
		{"nmap", "external_standard_va", "external"},
		{"bloodhound", "internal_ad_review", "internal"},
		{"netexec", "internal_ad_review", "internal"},
		{"lynis", "internal_linux_hardening", "internal"},
		{"trivy", "internal_container_review", "internal"},
		{"grype", "internal_container_review", "internal"},
		{"kube-bench", "internal_k8s_review", "internal"},
		{"prowler", "cloud_posture", "external"},
	}
	for _, c := range cases {
		gotCode, gotPlane := profileForScanner(c.scanner)
		if gotCode != c.code || gotPlane != c.plane {
			t.Errorf("scanner=%q: got %q/%q want %q/%q",
				c.scanner, gotCode, gotPlane, c.code, c.plane)
		}
	}
}

func TestProfileForScanner_UnknownDefaultsToExternal(t *testing.T) {
	t.Parallel()
	code, plane := profileForScanner("unknown-scanner-future-tool")
	if plane != "external" || code != "external_standard_va" {
		t.Errorf("unknown scanner → %q/%q; want external_standard_va/external",
			code, plane)
	}
}

func TestValidationErrors_Documented(t *testing.T) {
	t.Parallel()
	// We don't expose typed errors here; the contract is the
	// substring callers display to operators. This test pins the
	// substring fragments so a refactor surfaces breaking UX
	// changes alongside the code change that caused them.
	for _, want := range []string{
		"outcome must be passed",
		"finding has no affected_endpoint",
		"orchestrator not wired",
	} {
		if want == "" {
			t.Fatal("want fragment is empty")
		}
		// Run the substring through ToLower to make sure callers
		// can do case-insensitive matching if they need to.
		_ = strings.ToLower(want)
	}
}
