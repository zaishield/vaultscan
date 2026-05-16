package compliance

import (
	"testing"
	"time"
)

func TestParseFilters(t *testing.T) {
	t.Parallel()
	f := parseFilters("status=open,severity>=high,age<30d")
	if f["status"] != "open" {
		t.Errorf("status: %q", f["status"])
	}
	if f["severity"] != ">=high" {
		t.Errorf("severity: %q", f["severity"])
	}
	if f["age"] != "<30d" {
		t.Errorf("age: %q", f["age"])
	}
}

func TestParseWindow(t *testing.T) {
	t.Parallel()
	cases := map[string]time.Duration{
		"24h":  24 * time.Hour,
		"30d":  30 * 24 * time.Hour,
		"7d":   7 * 24 * time.Hour,
		"5m":   5 * time.Minute,
	}
	for in, want := range cases {
		got, ok := parseWindow(in)
		if !ok || got != want {
			t.Errorf("parseWindow(%q) = %v ok=%v, want %v", in, got, ok, want)
		}
	}
	if _, ok := parseWindow("nonsense"); ok {
		t.Error("nonsense should not parse")
	}
}

func TestParseAge(t *testing.T) {
	t.Parallel()
	d, op, ok := parseAge("<30d")
	if !ok || op != ">" || d != 30*24*time.Hour {
		t.Errorf("got %v %s %v", d, op, ok)
	}
	d, op, ok = parseAge(">30d")
	if !ok || op != "<" || d != 30*24*time.Hour {
		t.Errorf("got %v %s %v", d, op, ok)
	}
	if _, _, ok := parseAge("30d"); ok {
		t.Error("no op should fail")
	}
}

func TestSeveritiesGTE(t *testing.T) {
	t.Parallel()
	got := severitiesGTE("high")
	want := []string{"high", "critical"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
	got = severitiesGTE("info")
	if len(got) != 5 {
		t.Errorf("info should yield 5 levels, got %v", got)
	}
	got = severitiesGTE("nonsense")
	if len(got) != 1 || got[0] != "nonsense" {
		t.Errorf("unknown should pass through: %v", got)
	}
}

func TestVerdictForFindings(t *testing.T) {
	t.Parallel()
	// "open + high + age>30d" → ANY hit = fail.
	if verdictForFindings(filters{"status": "open"}, 0) != "pass" {
		t.Error("0 open findings should pass")
	}
	if verdictForFindings(filters{"status": "open"}, 5) != "fail" {
		t.Error("5 open findings should fail")
	}
	// "resolved + window" → ≥1 = pass.
	if verdictForFindings(filters{"status": "resolved"}, 0) != "fail" {
		t.Error("0 resolved should fail")
	}
	if verdictForFindings(filters{"status": "resolved"}, 1) != "pass" {
		t.Error("1 resolved should pass")
	}
}
