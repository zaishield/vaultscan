package enrichment

import (
	"testing"
	"testing/quick"
)

// Property-based tests for the severity-bump engine. The contract is
// fundamentally a partial order: bump never *downgrades* severity,
// only promotes or returns "" (no-op). We encode this as properties
// and let quick.Check find violations.

// Severity ordering (from rank()):
//   info < low < medium < high < critical
var sevs = []string{"info", "low", "medium", "high", "critical"}

func rankIdx(s string) int {
	for i, v := range sevs {
		if v == s {
			return i
		}
	}
	return -1
}

func TestProperty_SeverityBump_NeverDowngrades(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	f := func(curIdx uint8, cvss float64, epss float64, kev bool) bool {
		curIdx = curIdx % uint8(len(sevs))
		cur := sevs[curIdx]
		// Clamp cvss to a reasonable range so the test doesn't waste
		// cycles on NaN / Inf / out-of-band values.
		if cvss < 0 {
			cvss = 0
		}
		if cvss > 10 {
			cvss = 10
		}
		if epss < 0 {
			epss = 0
		}
		if epss > 1 {
			epss = 1
		}
		got := c.SeverityBump(cur, &EnrichmentResult{
			CVE: "CVE-x", CVSS: cvss, EPSSPercentile: epss, KEV: kev,
		})
		if got == "" {
			return true // explicit no-op is always safe
		}
		newIdx := rankIdx(got)
		oldIdx := rankIdx(cur)
		if newIdx < 0 {
			return false // never invent an unknown severity
		}
		// Promotion only — never strictly less than current
		return newIdx >= oldIdx
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestProperty_SeverityBump_KEVAlwaysCritical(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	f := func(curIdx uint8, cvss float64, epss float64) bool {
		curIdx = curIdx % uint8(len(sevs))
		cur := sevs[curIdx]
		got := c.SeverityBump(cur, &EnrichmentResult{
			CVE: "CVE-x", CVSS: cvss, EPSSPercentile: epss, KEV: true,
		})
		return got == "critical"
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestProperty_SeverityBump_EmptyCVEReturnsEmpty(t *testing.T) {
	t.Parallel()
	c := &CVEEnricher{}
	f := func(cur string, cvss float64, epss float64, kev bool) bool {
		got := c.SeverityBump(cur, &EnrichmentResult{
			CVE: "", CVSS: cvss, EPSSPercentile: epss, KEV: kev,
		})
		return got == ""
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 300}); err != nil {
		t.Fatal(err)
	}
}
