package compliance

import (
	"testing"
)

// Compliance evidence-query strings come from control definitions
// authored by operators (or imported from CIS / NIST templates).
// parseFilters runs over every one of them at evaluation time. A
// panic on a malformed filter would block the entire compliance
// evaluator pass — kill one tenant's compliance scoring globally —
// so we fuzz it to prove the parser is total over arbitrary inputs.
func FuzzParseFilters(f *testing.F) {
	seeds := []string{
		``,
		`severity=high`,
		`severity>=high,age<30d`,
		`severity<critical,window=24h`,
		`,,,`,
		`=`,
		`key=`,
		`=value`,
		`a=b=c`,
		`severity>=high,severity<critical`,
		`window=24h,window=30d`,
		"\t\nseverity=high\n",
		`key>>value`,
		`key>=value<other`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := parseFilters(in)
		// Contract: parser never panics and never returns a nil map.
		if out == nil {
			t.Fatalf("parseFilters(%q) returned nil map", in)
		}
		// Keys must be non-empty (an empty key would later collide
		// with the default case and yield ambiguous matches).
		for k := range out {
			if k == "" {
				t.Fatalf("parseFilters(%q) produced empty-string key", in)
			}
		}
	})
}

// FuzzParseWindow validates the duration mini-language is safe to
// expose to operator-authored controls.
func FuzzParseWindow(f *testing.F) {
	for _, s := range []string{"", "24h", "30d", "7d", "0d", "1m", "-1h", "abc", "999999999999d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = parseWindow(in)
	})
}

// FuzzParseAge ensures the age<…d / age>…d shorthand is panic-free.
func FuzzParseAge(f *testing.F) {
	for _, s := range []string{"", "<30d", ">7d", "30d", "<", ">", "<<30d", "<-1d", "<abc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_, _, _ = parseAge(in)
	})
}
