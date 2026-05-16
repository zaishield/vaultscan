package enrichment

import (
	"testing"
)

// SeverityBump is the override engine's data feed — every finding the
// platform ingests is run through it. A regression here silently
// inflates or deflates customer-visible severities, which directly
// affects SLAs and remediation priority.

func TestSeverityBump_KEVAlwaysCritical(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	// Any KEV-listed CVE bumps to critical, regardless of current sev.
	for _, cur := range []string{"info", "low", "medium", "high", ""} {
		got := c.SeverityBump(cur, &EnrichmentResult{CVE: "CVE-2024-0001", KEV: true})
		if got != "critical" {
			t.Errorf("KEV from %q should bump to critical, got %q", cur, got)
		}
	}
}

func TestSeverityBump_KEVDoesNotDowngrade(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	// Edge case: caller already passed "critical". Bump returns
	// "critical" anyway (no logical change but also no downgrade).
	got := c.SeverityBump("critical", &EnrichmentResult{CVE: "CVE-2024-0001", KEV: true})
	if got != "critical" {
		t.Errorf("got %q from KEV+critical input — must remain critical", got)
	}
}

func TestSeverityBump_EPSSHighPercentile(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	r := &EnrichmentResult{CVE: "CVE-2024-0002", EPSSPercentile: 0.96}
	if got := c.SeverityBump("low", r); got != "high" {
		t.Errorf("EPSS 0.96 from low should bump to high, got %q", got)
	}
	// Below threshold (0.95)
	r2 := &EnrichmentResult{CVE: "CVE-2024-0002", EPSSPercentile: 0.94}
	if got := c.SeverityBump("low", r2); got != "" {
		t.Errorf("EPSS 0.94 should NOT bump, got %q", got)
	}
}

func TestSeverityBump_CVSSBands(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	cases := []struct {
		cur     string
		cvss    float64
		want    string
		comment string
	}{
		{"low", 9.5, "critical", "9+ → critical"},
		{"low", 7.5, "high", "7-9 → high"},
		{"low", 4.5, "medium", "4-7 → medium"},
		{"low", 3.0, "", "<4 no bump"},
		{"critical", 9.5, "", "already critical, no bump"},
		{"high", 9.5, "critical", "high → critical via 9+"},
		{"medium", 7.5, "high", "medium → high via 7+"},
	}
	for _, tc := range cases {
		got := c.SeverityBump(tc.cur, &EnrichmentResult{CVE: "x", CVSS: tc.cvss})
		if got != tc.want {
			t.Errorf("%s: cur=%q cvss=%v got=%q want=%q",
				tc.comment, tc.cur, tc.cvss, got, tc.want)
		}
	}
}

func TestSeverityBump_NilOrEmptyResult_NoBump(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	if got := c.SeverityBump("low", nil); got != "" {
		t.Errorf("nil result must not bump, got %q", got)
	}
	if got := c.SeverityBump("low", &EnrichmentResult{}); got != "" {
		t.Errorf("empty result must not bump, got %q", got)
	}
}

func TestRank_Ordering(t *testing.T) {
	t.Parallel()
	order := []string{"info", "low", "medium", "high", "critical"}
	prev := -1
	for _, s := range order {
		r := rank(s)
		if r <= prev {
			t.Errorf("rank(%q)=%d not greater than previous %d", s, r, prev)
		}
		prev = r
	}
	if rank("nonsense") != 0 && rank("nonsense") != 1 {
		// rank for unknown levels must be at or below "info" so the
		// bump logic always treats it as upgradable.
		t.Errorf("rank for unknown severity should be ≤info, got %d", rank("nonsense"))
	}
}

func TestLoadNVD_RejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	if _, err := c.LoadNVD(nil, []byte("not-json")); err == nil {
		t.Error("LoadNVD should reject non-JSON")
	}
}

// FuzzSeverityBump — the override engine is on every finding's hot
// path. We test it never panics on arbitrary inputs.
func FuzzSeverityBump(f *testing.F) {
	f.Add("low", 7.5, 0.5, false)
	f.Add("", -1.0, 1.5, true)
	f.Add("critical", 0.0, 0.0, false)
	c := &CVEEnricher{}
	f.Fuzz(func(t *testing.T, cur string, cvss float64, epss float64, kev bool) {
		_ = c.SeverityBump(cur, &EnrichmentResult{
			CVE: "x", CVSS: cvss, EPSSPercentile: epss, KEV: kev,
		})
	})
}
