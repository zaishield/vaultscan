package notify

import (
	"testing"
	"time"
)

func TestSeverityRank(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	// QUIET 9-17 UTC; everything outside that window is LOUD.
	// (See quietHoursSpec doc — fields name the quiet window, not
	// the business window. The previous implementation inverted
	// these semantics, making a 9-17 spec quiet OVERNIGHT.)
	spec := []byte(`{"timezone":"UTC","start_hour":9,"end_hour":17}`)
	cases := []struct {
		hour int
		want bool
	}{
		{8, false},  // before quiet starts → not quiet
		{9, true},   // start of quiet
		{12, true},  // mid-quiet
		{16, true},  // last hour of quiet
		{17, false}, // quiet window closed
		{22, false}, // late night not in the spec → not quiet
	}
	for _, c := range cases {
		when := time.Date(2026, 5, 15, c.hour, 0, 0, 0, time.UTC)
		if got := inQuietHours(spec, when); got != c.want {
			t.Errorf("hour=%d: got %v, want %v", c.hour, got, c.want)
		}
	}
}

func TestInQuietHours_WrapAroundMidnight(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	// quiet 9-17 weekdays. On weekends quiet hours don't apply
	// (the rule is "no notifications during weekday work hours").
	spec := []byte(`{"timezone":"UTC","start_hour":9,"end_hour":17,"weekday_only":true}`)
	// 2026-05-16 is a Saturday — weekday_only=true means quiet
	// hours don't apply on weekends → loud.
	sat := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	if inQuietHours(spec, sat) {
		t.Error("weekday_only: Saturday noon should NOT be quiet (weekend = rule doesn't apply)")
	}
	// 2026-05-15 is a Friday at noon — inside the 9-17 quiet
	// window AND it's a weekday → quiet.
	fri := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if !inQuietHours(spec, fri) {
		t.Error("weekday_only: Friday noon should be quiet (inside 9-17 quiet window)")
	}
}

func TestInQuietHours_TimezoneApplies(t *testing.T) {
	t.Parallel()
	// quiet 9-17 ET — i.e. user wants no notifications during ET
	// business hours (9-17 = quiet window).
	spec := []byte(`{"timezone":"America/New_York","start_hour":9,"end_hour":17}`)
	// 2026-05-15 14:00 UTC = 10:00 ET — INSIDE the quiet window.
	when := time.Date(2026, 5, 15, 14, 0, 0, 0, time.UTC)
	if !inQuietHours(spec, when) {
		t.Error("14 UTC = 10 ET = inside 9-17 quiet window → should be quiet")
	}
	// 2026-05-15 23:00 UTC = 19:00 ET — OUTSIDE the quiet window.
	when = time.Date(2026, 5, 15, 23, 0, 0, 0, time.UTC)
	if inQuietHours(spec, when) {
		t.Error("23 UTC = 19 ET = outside 9-17 quiet window → should NOT be quiet")
	}
}

// Invalid timezone strings should never panic and should return
// "not quiet" — fail-safe = always-loud rather than always-silent.
// Without this test a regression that flipped the fallback to true
// would silently mute notifications for users with corrupt prefs.
func TestInQuietHours_InvalidTimezoneFallsThroughNotQuiet(t *testing.T) {
	t.Parallel()
	spec := []byte(`{"timezone":"Etc/Definitely-Not-Real","start_hour":9,"end_hour":17}`)
	when := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if inQuietHours(spec, when) {
		t.Error("invalid timezone should fall through to NOT quiet (fail-safe loud)")
	}
}

// Wrap-midnight quiet + WeekdayOnly: on a weekend the rule should
// not apply at all, even though the wrap-midnight hour math would
// otherwise mark 23:00 as quiet. Regression catcher for the audit
// finding about the WeekdayOnly check being skipped in the
// wrap-midnight branch.
func TestInQuietHours_WrapMidnightWeekdayOnlyOnWeekend(t *testing.T) {
	t.Parallel()
	spec := []byte(`{"timezone":"UTC","start_hour":22,"end_hour":6,"weekday_only":true}`)
	// 2026-05-16 is Saturday. 23:00 would be inside the quiet
	// wrap-midnight window — BUT weekday_only=true means the rule
	// doesn't apply on weekends.
	sat := time.Date(2026, 5, 16, 23, 0, 0, 0, time.UTC)
	if inQuietHours(spec, sat) {
		t.Error("Saturday 23:00 with weekday_only=true should NOT be quiet")
	}
	// 2026-05-15 is Friday. 23:00 is inside the wrap-midnight quiet
	// window AND it's a weekday → should be quiet.
	fri := time.Date(2026, 5, 15, 23, 0, 0, 0, time.UTC)
	if !inQuietHours(spec, fri) {
		t.Error("Friday 23:00 with weekday_only=true should be quiet")
	}
}

func TestInQuietHours_BadJSONIsNotQuiet(t *testing.T) {
	t.Parallel()
	if inQuietHours([]byte("not json"), time.Now()) {
		t.Error("bad JSON should default to NOT quiet (don't silence by accident)")
	}
}

func TestInQuietHours_EmptyTimezoneIsNotQuiet(t *testing.T) {
	t.Parallel()
	if inQuietHours([]byte(`{}`), time.Now()) {
		t.Error("empty quiet hours config = no quiet window")
	}
}
