package engagements

import (
	"net"
	"testing"
)

// IntensityRank is consulted on every Scope Guard decision — if a
// scan-job's profile out-ranks the engagement's, the job is refused.
// A regression here either over-permits (security risk) or denies
// legitimate work.

func TestIntensityRank_KnownLevels(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"light":      1,
		"standard":   2,
		"aggressive": 3,
	}
	for in, want := range cases {
		if got := IntensityRank(in); got != want {
			t.Errorf("IntensityRank(%q)=%d want %d", in, got, want)
		}
	}
}

func TestIntensityRank_UnknownIsZero(t *testing.T) {
	t.Parallel()
	// Unknown intensities must rank 0 so any real engagement
	// intensity out-ranks them — fail-closed.
	for _, in := range []string{"", "extreme", "STANDARD", "default"} {
		if got := IntensityRank(in); got != 0 {
			t.Errorf("IntensityRank(%q)=%d want 0 (fail-closed)", in, got)
		}
	}
}

func TestIntensityRank_Monotonic(t *testing.T) {
	t.Parallel()
	if IntensityRank("light") >= IntensityRank("standard") {
		t.Error("light must rank below standard")
	}
	if IntensityRank("standard") >= IntensityRank("aggressive") {
		t.Error("standard must rank below aggressive")
	}
}

func TestIPOrNull(t *testing.T) {
	t.Parallel()
	if v := ipOrNull(nil); v != nil {
		t.Errorf("nil IP must map to nil, got %v", v)
	}
	ip := net.ParseIP("10.0.0.1")
	if v := ipOrNull(ip); v != "10.0.0.1" {
		t.Errorf("ipOrNull(10.0.0.1)=%v want \"10.0.0.1\"", v)
	}
}

func TestNullIfEmpty(t *testing.T) {
	t.Parallel()
	if v := nullIfEmpty(""); v != nil {
		t.Errorf("empty must be nil, got %v", v)
	}
	if v := nullIfEmpty("x"); v != "x" {
		t.Errorf("\"x\" must pass through, got %v", v)
	}
}
