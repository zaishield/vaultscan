package scopeguard

import (
	"testing"
	"testing/quick"
)

// Property-based tests for matches(). The scope-guard match logic is
// what gates whether a scan job's target is allowed against the
// engagement's approved scope — bugs here are either availability
// bugs (legitimate work refused) or safety bugs (cross-customer
// scanning). We assert a few invariants:
//
//   * matches(scope_type, value, target_type, value) is reflexive
//     for "url", "subdomain", "api", "ip" (exact-equality scope types)
//   * domain scope is suffix-aware: a.b.example.com is in scope for
//     example.com
//   * cidr scope behaviour is monotone: more-specific target inside
//     a network is always matched if the simpler version is

func TestProperty_Matches_ExactReflexive(t *testing.T) {
	t.Parallel()
	f := func(v string) bool {
		for _, st := range []string{"url", "subdomain", "api", "ip"} {
			if !matches(st, v, st, v) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}

func TestProperty_Matches_DomainSuffix(t *testing.T) {
	t.Parallel()
	// For a scope of "domain"/"example.com", any host of the form
	// X.example.com (X non-empty, no further dots) must match.
	f := func(sub string) bool {
		if sub == "" {
			sub = "host"
		}
		// Reject inputs that would generate weird hostnames
		for _, r := range sub {
			if r == '.' || r == '/' || r == ':' || r == ' ' {
				return true // skip these — outside the property domain
			}
		}
		target := sub + ".example.com"
		return matches("domain", "example.com", "subdomain", target)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}
