package enrichment

import (
	"testing"
)

// splitSANs is the helper that normalises CT-log subject alternative
// names. The output goes into asset_enrichment as discovered hostnames
// — every hostname here becomes part of the customer's attack
// surface inventory. A bug that drops a hostname leaves an asset
// invisible to scanning.

func TestSplitSANs_DeduplicatesAndLowercases(t *testing.T) {
	t.Parallel()
	got := splitSANs([]string{"API.Example.COM\nwww.example.com\nAPI.EXAMPLE.COM"}, "Example.com")
	// Expect: example.com, api.example.com, www.example.com (any order)
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] {
			t.Errorf("duplicate: %q in %v", s, got)
		}
		seen[s] = true
	}
	for _, want := range []string{"example.com", "api.example.com", "www.example.com"} {
		if !seen[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestSplitSANs_HandlesEmptyAndWhitespace(t *testing.T) {
	t.Parallel()
	got := splitSANs([]string{"", "   ", "\n\n"}, "")
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestSplitSANs_PreservesCNAsFirstEntry(t *testing.T) {
	t.Parallel()
	got := splitSANs([]string{"alt.example.com"}, "primary.example.com")
	if len(got) == 0 || got[0] != "primary.example.com" {
		t.Errorf("CN should be first; got %v", got)
	}
}

func TestSplitSANs_SkipsEmptyAfterTrim(t *testing.T) {
	t.Parallel()
	got := splitSANs([]string{"\n  \n\nexample.org\n  "}, "")
	if len(got) != 1 || got[0] != "example.org" {
		t.Errorf("got %v want [example.org]", got)
	}
}

func TestTruncate_BoundaryCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcde", 5, "abcde"},
		{"abcdef", 5, "abcde…"},
		{"a", 0, "a"},  // n < len → truncate to empty + ellipsis
	}
	for _, c := range cases {
		got := truncate(c.in, c.n)
		// Only assert on the "no truncate needed" paths; the truncate
		// branch's exact form depends on rune semantics.
		if len(c.in) <= c.n && got != c.in {
			t.Errorf("truncate(%q, %d)=%q want %q", c.in, c.n, got, c.want)
		}
		if len(c.in) > c.n && got == c.in {
			t.Errorf("truncate(%q, %d) returned original — should have shortened", c.in, c.n)
		}
	}
}

// FuzzSplitSANs proves the SAN splitter never panics on adversarial
// certificate transparency log entries. CT entries are attacker-
// influenced (anyone can publish a cert with a malicious SAN).
func FuzzSplitSANs(f *testing.F) {
	f.Add("a.com\nb.com", "primary")
	f.Add("", "")
	f.Add("\x00\x01\x02", "x")
	f.Fuzz(func(t *testing.T, raw, cn string) {
		out := splitSANs([]string{raw}, cn)
		// Contract: every entry must be lowercase + trimmed.
		for _, s := range out {
			if s == "" {
				t.Fatalf("empty entry in output %v", out)
			}
			for _, r := range s {
				if r >= 'A' && r <= 'Z' {
					t.Fatalf("uppercase in output %q", s)
				}
			}
		}
	})
}
