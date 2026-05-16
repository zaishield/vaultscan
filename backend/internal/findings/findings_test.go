package findings

import (
	"testing"

	"github.com/google/uuid"
)

func TestDedupFingerprintStable(t *testing.T) {
	t.Parallel()
	a := IngestInput{
		Title: "X-Frame-Options missing", Scanner: "zap",
		AffectedEndpoint: "https://api.example.com",
		CVE: "", CWE: "1021", Port: 443, Protocol: "tcp", Severity: "low",
	}
	b := a
	if dedupFingerprint(a) != dedupFingerprint(b) {
		t.Fatal("dedup must be stable for identical inputs")
	}
	c := a
	c.AffectedEndpoint = "https://other.example.com"
	if dedupFingerprint(a) == dedupFingerprint(c) {
		t.Fatal("dedup must distinguish different endpoints")
	}
}

func TestAllowedTransitions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		from, to string
		allowed  bool
	}{
		{"open", "triaged", true},
		{"open", "remediated", false},
		{"remediated", "retest_requested", true},
		{"retest_requested", "retest_passed", true},
		{"retest_requested", "open", false},
		{"closed", "open", true},
		{"closed", "remediated", false},
	}
	for _, tc := range cases {
		got := AllowedTransitions[tc.from][tc.to]
		if got != tc.allowed {
			t.Fatalf("%s -> %s allowed=%v want=%v", tc.from, tc.to, got, tc.allowed)
		}
	}
}

func TestValidStatuses(t *testing.T) {
	t.Parallel()
	if len(ValidStatuses()) != 11 {
		t.Fatalf("Blueprint §17.3 mandates 11 statuses, got %d", len(ValidStatuses()))
	}
}

// IngestInput must include the fields needed for the canonical model in §17.2.
func TestIngestInputShape(t *testing.T) {
	t.Parallel()
	in := IngestInput{TenantID: uuid.New(), Title: "X", Severity: "high", Scanner: "nuclei"}
	fp := dedupFingerprint(in)
	if fp == "" {
		t.Fatal("fingerprint must not be empty")
	}
}
