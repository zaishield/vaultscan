package notify

import (
	"testing"
	"time"
)

func TestSeverityRank(t *testing.T) {
	if severityRank("low") >= severityRank("high") {
		t.Error("low should rank below high")
	}
	if severityRank("critical") <= severityRank("medium") {
		t.Error("critical should outrank medium")
	}
	if severityRank("nonsense") != 0 {
		t.Errorf("unknown severity should rank 0, got %d", severityRank("nonsense"))
	}
}

func TestMatchesPrefix(t *testing.T) {
	cases := []struct {
		prefix, eventType string
		want              bool
	}{
		{"*", "FindingNormalized", true},
		{"", "FindingNormalized", true},
		{"Finding", "FindingNormalized", true},
		{"Finding", "FindingDeduplicated", true},
		{"FindingNormalized", "FindingNormalized", true},
		{"FindingNormalized", "FindingDeduplicated", false},
		{"ScanJob", "FindingNormalized", false},
	}
	for _, c := range cases {
		if got := matchesPrefix(c.prefix, c.eventType); got != c.want {
			t.Errorf("matchesPrefix(%q,%q)=%v want %v",
				c.prefix, c.eventType, got, c.want)
		}
	}
}

func TestInQuietHours_SameDayWindow(t *testing.T) {
	// Business hours 9-17 UTC; quiet OUTSIDE that window.
	spec := []byte(`{"timezone":"UTC","start_hour":9,"end_hour":17}`)
	cases := []struct {
		hour int
		want bool
	}{
		{8, true},   // before window → quiet
		{9, false},  // start of window → not quiet
		{12, false}, // mid-window
		{16, false}, // last hour
		{17, true},  // window closed
		{22, true},  // late night
	}
	for _, c := range cases {
		when := time.Date(2026, 5, 15, c.hour, 0, 0, 0, time.UTC)
		if got := inQuietHours(spec, when); got != c.want {
			t.Errorf("hour=%d: got %v, want %v", c.hour, got, c.want)
		}
	}
}

func TestInQuietHours_WrapAroundMidnight(t *testing.T) {
	// Quiet 22-06 UTC (overnight).
	spec := []byte(`{"timezone":"UTC","start_hour":22,"end_hour":6}`)
	cases := []struct {
		hour int
		want bool
	}{
		{21, false}, // just before quiet
		{22, true},  // start of quiet
		{2, true},   // middle of night
		{5, true},   // last hour
		{6, false},  // quiet ends
		{12, false}, // daytime
	}
	for _, c := range cases {
		when := time.Date(2026, 5, 15, c.hour, 0, 0, 0, time.UTC)
		if got := inQuietHours(spec, when); got != c.want {
			t.Errorf("hour=%d: got %v, want %v", c.hour, got, c.want)
		}
	}
}

func TestInQuietHours_WeekdayOnly(t *testing.T) {
	spec := []byte(`{"timezone":"UTC","start_hour":9,"end_hour":17,"weekday_only":true}`)
	// 2026-05-16 is a Saturday — entire day is quiet.
	sat := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	if !inQuietHours(spec, sat) {
		t.Error("weekday_only: Saturday noon should be quiet")
	}
	// 2026-05-15 is a Friday at noon — inside business hours, not quiet.
	fri := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if inQuietHours(spec, fri) {
		t.Error("weekday_only: Friday noon should NOT be quiet")
	}
}

func TestInQuietHours_TimezoneApplies(t *testing.T) {
	spec := []byte(`{"timezone":"America/New_York","start_hour":9,"end_hour":17}`)
	// 2026-05-15 14:00 UTC = 10:00 ET — inside business hours, not quiet.
	when := time.Date(2026, 5, 15, 14, 0, 0, 0, time.UTC)
	if inQuietHours(spec, when) {
		t.Error("14 UTC should be 10 ET = inside business → not quiet")
	}
	// 2026-05-15 23:00 UTC = 19:00 ET — after business hours, quiet.
	when = time.Date(2026, 5, 15, 23, 0, 0, 0, time.UTC)
	if !inQuietHours(spec, when) {
		t.Error("23 UTC should be 19 ET = outside business → quiet")
	}
}

func TestInQuietHours_BadJSONIsNotQuiet(t *testing.T) {
	if inQuietHours([]byte("not json"), time.Now()) {
		t.Error("bad JSON should default to NOT quiet (don't silence by accident)")
	}
}

func TestInQuietHours_EmptyTimezoneIsNotQuiet(t *testing.T) {
	if inQuietHours([]byte(`{}`), time.Now()) {
		t.Error("empty quiet hours config = no quiet window")
	}
}
