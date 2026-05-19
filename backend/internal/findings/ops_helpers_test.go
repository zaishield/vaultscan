// ops_helpers_test.go — unit tests for the pure helpers in ops.go
// that the existing test file doesn't cover: severityRank ordering
// edge cases (unknown severities, casing) and the suppression-rule
// case-insensitive regex matcher.
//
// Service-level Upsert / Transition / SweepSLABreaches /
// EvaluateSuppression / AttachCluster all touch the DB and live
// in the integration suite (test/integration/enterprise_lifecycle_e2e_test.go,
// metrics_emission_test.go, hs06_acceptance_test.go). Re-running
// those here would require a testcontainers harness that's already
// owned by the integration package; we don't duplicate.
package findings

import (
	"testing"
)

func TestSeverityRank_UnknownAndCasing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want int
	}{
		{"CRITICAL", 5},
		{"Critical", 5},
		{"critical", 5},
		{"HIGH", 4},
		{"medium", 3},
		{"low", 2},
		{"info", 1},
		{"informational", 0}, // not in the switch — returns 0
		{"", 0},
		{"bogus", 0},
	}
	for _, tc := range cases {
		if got := severityRank(tc.in); got != tc.want {
			t.Errorf("severityRank(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestMatchesCaseInsensitive_HappyAndAnchoring(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"apache", "Apache HTTP Server", true},
		{"apache", "nginx", false},
		{"^cve-2024-", "CVE-2024-12345", true},
		{"^cve-2023-", "CVE-2024-12345", false},
		// Regex anchors / metachars
		{"java\\b", "javascript runtime", false},
		{"java\\b", "java runtime", true},
		{"(eternal|zerologon)", "EternalBlue", true},
		{"(eternal|zerologon)", "FauxLogon", false},
		// Empty pattern matches every value (regexp semantics).
		{"", "anything", true},
		// Bad regex → match must be false, NOT panic.
		{"(unclosed", "anything", false},
	}
	for _, tc := range cases {
		if got := matchesCaseInsensitive(tc.pattern, tc.value); got != tc.want {
			t.Errorf("matchesCaseInsensitive(%q, %q) = %v, want %v",
				tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestClusterKey_StableAcrossPortNoise(t *testing.T) {
	t.Parallel()
	in1 := IngestInput{
		Scanner: "nuclei", CVE: "CVE-2024-99999",
		Title: "RCE in Apache via /admin/console:8080",
	}
	in2 := IngestInput{
		Scanner: "nuclei", CVE: "CVE-2024-99999",
		Title: "RCE in Apache via /admin/console:9090",
	}
	if ClusterKey(in1) != ClusterKey(in2) {
		t.Errorf("expected ports in title to be stripped before clustering:\n\t%q\n\t%q",
			ClusterKey(in1), ClusterKey(in2))
	}
}
