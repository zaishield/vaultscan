package dashboards

import (
	"testing"
	"time"
)

func TestComputeRiskScore_Weights(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		x    *Executive
		want float64
	}{
		{"empty", &Executive{}, 0},
		{"one-critical", &Executive{CriticalFindings: 1}, 10},
		{"one-high", &Executive{HighFindings: 1}, 5},
		{"one-sla", &Executive{SLABreaches: 1}, 7},
		{"mixed-under-cap", &Executive{CriticalFindings: 2, HighFindings: 2}, 30},
		{"capped-at-100", &Executive{CriticalFindings: 100}, 100},
		{"hard-cap", &Executive{CriticalFindings: 50, HighFindings: 50, SLABreaches: 50}, 100},
	}
	for _, c := range cases {
		got := computeRiskScore(c.x)
		if got != c.want {
			t.Errorf("%s: computeRiskScore = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseRange_KnownPresets(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cases := []struct {
		spec       string
		wantSinceZero bool        // true → ParseRange returns Range{} (no lower bound)
		approxAgo  time.Duration  // wantSinceZero=false → Since ≈ now - approxAgo
	}{
		{"", false, 30 * 24 * time.Hour},          // default
		{"30d", false, 30 * 24 * time.Hour},
		{"24h", false, 24 * time.Hour},
		{"7d", false, 7 * 24 * time.Hour},
		{"all", true, 0},
		{"1h", false, 1 * time.Hour},
		{"junk-garbage-xx", false, 30 * 24 * time.Hour}, // fallback
	}
	for _, c := range cases {
		r := ParseRange(c.spec)
		if c.wantSinceZero {
			if !r.Since.IsZero() {
				t.Errorf("%q: expected Since zero, got %v", c.spec, r.Since)
			}
			continue
		}
		delta := now.Sub(r.Since)
		// 5-second slack for the test running between now+ParseRange.
		if delta < c.approxAgo-5*time.Second || delta > c.approxAgo+5*time.Second {
			t.Errorf("%q: Since ago=%v, want ~%v", c.spec, delta, c.approxAgo)
		}
	}
}
