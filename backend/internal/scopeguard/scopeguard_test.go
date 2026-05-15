package scopeguard

import "testing"

// matches() is the in-scope predicate used by Scope Guard. The test exercises
// every branch (domain/subdomain, exact IP, CIDR-in-CIDR, mismatch) so that
// regressions in the legal gate are caught before they ship.
func TestMatches(t *testing.T) {
	cases := []struct {
		name       string
		scopeType  string
		scopeValue string
		targetType string
		target     string
		want       bool
	}{
		{"exact domain", "domain", "example.com", "domain", "example.com", true},
		{"subdomain of approved", "domain", "example.com", "domain", "api.example.com", true},
		{"unrelated domain rejected", "domain", "example.com", "domain", "evil.com", false},
		{"ip in cidr", "cidr", "10.0.0.0/8", "ip", "10.5.6.7", true},
		{"ip outside cidr", "cidr", "10.0.0.0/8", "ip", "11.0.0.1", false},
		{"narrower cidr inside wider", "cidr", "10.0.0.0/8", "cidr", "10.1.0.0/16", true},
		{"wider cidr not contained", "cidr", "10.1.0.0/16", "cidr", "10.0.0.0/8", false},
		{"url exact", "url", "https://example.com/api", "url", "https://example.com/api", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matches(tc.scopeType, tc.scopeValue, tc.targetType, tc.target); got != tc.want {
				t.Fatalf("matches(%q, %q, %q, %q) = %v; want %v",
					tc.scopeType, tc.scopeValue, tc.targetType, tc.target, got, tc.want)
			}
		})
	}
}
