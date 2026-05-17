package notify

import "testing"

// matchesPrefix is the per-channel routing predicate. Tested
// because event-type strings are stable contracts; a regression
// here silently disables an entire subscription class.

func TestMatchesPrefix_WildcardMatches(t *testing.T) {
	t.Parallel()
	for _, ev := range []string{"finding.created", "scan.completed", ""} {
		if !matchesPrefix("*", ev) {
			t.Errorf("wildcard should match %q", ev)
		}
	}
}

func TestMatchesPrefix_EmptyMatches(t *testing.T) {
	t.Parallel()
	if !matchesPrefix("", "finding.created") {
		t.Error("empty prefix should match (treat as no filter)")
	}
}

func TestMatchesPrefix_LiteralPrefix(t *testing.T) {
	t.Parallel()
	if !matchesPrefix("finding.", "finding.created") {
		t.Error("expected prefix to match")
	}
	if matchesPrefix("finding.", "scan.completed") {
		t.Error("non-matching prefix should not match")
	}
}

func TestMatchesPrefix_CaseSensitive(t *testing.T) {
	t.Parallel()
	// Convention is PascalCase event types. The matcher is case-
	// sensitive so a typo in the prefix surfaces as no-match.
	if matchesPrefix("FINDING.", "finding.created") {
		t.Error("matcher should be case-sensitive (caller normalises)")
	}
}

// severityRank — used by the severity floor on each preference row.
// The map is the source of truth; we just check it stays monotone.

func TestSeverityRank_StrictOrdering(t *testing.T) {
	t.Parallel()
	order := []string{"info", "low", "medium", "high", "critical"}
	last := -1
	for _, s := range order {
		r := severityRank(s)
		if r <= last {
			t.Errorf("severity %s rank %d not greater than prev %d", s, r, last)
		}
		last = r
	}
}

func TestSeverityRank_UnknownIsZero(t *testing.T) {
	t.Parallel()
	if severityRank("ultra-critical") != 0 {
		t.Errorf("unknown severity should rank 0, got %d", severityRank("ultra-critical"))
	}
}

func TestSeverityRank_CaseInsensitive(t *testing.T) {
	t.Parallel()
	if severityRank("HIGH") != severityRank("high") {
		t.Error("severity rank should be case-insensitive")
	}
}

// nullIfEmptyString helper — used to convert "" → SQL NULL on
// optional columns. Returning the empty string would insert ''
// which downstream filters can't distinguish from "user typed
// nothing".

func TestNullIfEmptyString(t *testing.T) {
	t.Parallel()
	if got := nullIfEmptyString(""); got != nil {
		t.Errorf("empty → %v want nil", got)
	}
	if got := nullIfEmptyString("hello"); got != "hello" {
		t.Errorf("non-empty → %v want hello", got)
	}
}
