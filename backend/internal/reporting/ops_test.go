package reporting

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Reporting service has several pure helpers driving the scheduled
// report cadence + the compliance-control DSL. These are tested
// without a DB so regressions surface fast in pre-merge.

func TestValidCadence(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"daily": true, "weekly": true, "monthly": true, "quarterly": true,
		"": false, "annually": false, "DAILY": false, "biweekly": false,
	}
	for in, want := range cases {
		if got := validCadence(in); got != want {
			t.Errorf("validCadence(%q)=%v want %v", in, got, want)
		}
	}
}

func TestCadenceNext_AdvancesCorrectly(t *testing.T) {
	t.Parallel()
	from := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		cadence string
		want    time.Time
	}{
		{"daily", from.Add(24 * time.Hour)},
		{"weekly", from.Add(7 * 24 * time.Hour)},
		{"monthly", from.AddDate(0, 1, 0)},
		{"quarterly", from.AddDate(0, 3, 0)},
		{"unknown", from.Add(24 * time.Hour)}, // defaults to daily
	}
	for _, c := range cases {
		got := cadenceNext(from, c.cadence)
		if !got.Equal(c.want) {
			t.Errorf("cadenceNext(%s)=%s want %s", c.cadence, got, c.want)
		}
	}
}

func TestCadenceNext_MonthlyHandlesEdgeOfMonth(t *testing.T) {
	t.Parallel()
	// Jan 31 + 1 month = Mar 3 (Feb has 28/29 days) per AddDate semantics.
	jan31 := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	got := cadenceNext(jan31, "monthly")
	if got.Year() != 2026 || got.Month() != 3 {
		t.Errorf("Jan 31 + 1 month → %s want March 2026", got)
	}
}

func TestParsePatterns_EmptyOrNull(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "  ", "[]", "null"} {
		if got := parsePatterns(in); got != nil {
			t.Errorf("parsePatterns(%q)=%v want nil", in, got)
		}
	}
}

func TestParsePatterns_TrimsQuotesAndBrackets(t *testing.T) {
	t.Parallel()
	got := parsePatterns(`["alpha", "beta", "gamma"]`)
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("parsePatterns count=%d want %d (got %v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("parsePatterns[%d]=%q want %q", i, got[i], w)
		}
	}
}

func TestParsePatterns_SkipsEmptyEntries(t *testing.T) {
	t.Parallel()
	got := parsePatterns(`["", "x", ""]`)
	if len(got) != 1 || got[0] != "x" {
		t.Errorf("parsePatterns dropping empties wrong: %v", got)
	}
}

func TestDetectPDFRenderer_AlwaysReturnsNonNil(t *testing.T) {
	t.Parallel()
	r := DetectPDFRenderer()
	if r == nil {
		t.Fatal("DetectPDFRenderer returned nil")
	}
	// Name must be one of the documented options.
	switch r.Name() {
	case "chromium", "html-fallback":
		// ok
	default:
		t.Errorf("renderer name=%q unexpected", r.Name())
	}
}

func TestHTMLFallbackRenderer_AnnotatesOutput(t *testing.T) {
	t.Parallel()
	r := htmlFallbackRenderer{}
	out, err := r.Render(context.Background(), []byte("<html></html>"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "VAULTSCAN-PDF-FALLBACK") {
		t.Errorf("fallback renderer must prepend sentinel header; got %s", out)
	}
}

func TestWriteAndReadTempFile_RoundTrip(t *testing.T) {
	t.Parallel()
	body := []byte("payload bytes")
	p, err := writeTempFile("vaultscan-test-*.tmp", body)
	if err != nil {
		t.Fatal(err)
	}
	defer removeTempFile(p)
	got, err := readFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("round-trip mismatch: got %q want %q", got, body)
	}
}

// Fuzz parsePatterns — comes from operator-authored compliance control
// definitions; an attacker who can edit a control row could feed
// pathological inputs.
func FuzzParsePatterns(f *testing.F) {
	f.Add(`["a","b"]`)
	f.Add(``)
	f.Add(`null`)
	f.Add(`[[[[`)
	f.Add(`","`)
	f.Add(`"escaped\"quote"`)
	f.Fuzz(func(t *testing.T, in string) {
		_ = parsePatterns(in) // panic-free is the contract
	})
}
