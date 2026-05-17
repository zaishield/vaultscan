package scopeguard

import "testing"

// intensityRank — ordering. Used by checkAggressiveProfile to gate
// "this profile is more aggressive than the engagement allows".
// Regression here = silent over-permissive profile selection.

func TestIntensityRank_Ordering(t *testing.T) {
	t.Parallel()
	if intensityRank("light") >= intensityRank("standard") {
		t.Error("light should rank below standard")
	}
	if intensityRank("standard") >= intensityRank("aggressive") {
		t.Error("standard should rank below aggressive")
	}
}

func TestIntensityRank_UnknownIsZero(t *testing.T) {
	t.Parallel()
	if intensityRank("ultra-aggressive") != 0 {
		t.Errorf("unknown intensity should rank 0, got %d", intensityRank("ultra-aggressive"))
	}
	if intensityRank("") != 0 {
		t.Errorf("empty intensity should rank 0")
	}
}

// Audit found: an engagement created without explicit intensity
// gets stored as "standard"; the rank function MUST therefore
// return non-zero for that string so the comparison works.
func TestIntensityRank_StandardIsRanked(t *testing.T) {
	t.Parallel()
	if intensityRank("standard") == 0 {
		t.Fatal("standard must have non-zero rank")
	}
}

// hostFromURL extracts the bare host. The matcher uses it when
// the target_type is "url" but the scope is "domain".

func TestHostFromURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://api.example.com:8443/x", "api.example.com"},
		{"https://example.com", "example.com"},
		{"https://example.com:443", "example.com"},
		{"https://example.com/?q=1", "example.com"},
		{"https://example.com#section", "example.com"},
		{"not-a-url", ""},
		{"", ""},
		{"//example.com/x", ""}, // no scheme
		{"ftp://files.example.com/x", "files.example.com"},
	}
	for _, c := range cases {
		got := hostFromURL(c.in)
		if got != c.want {
			t.Errorf("hostFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// matches() — additional edge cases on top of the existing
// TestMatches. The original test didn't cover IPv6, malformed
// CIDR, or whitespace + case handling.

func TestMatches_CaseInsensitive(t *testing.T) {
	t.Parallel()
	if !matches("domain", "Example.COM", "domain", "EXAMPLE.com") {
		t.Error("matches should be case-insensitive")
	}
}

func TestMatches_TrimsWhitespace(t *testing.T) {
	t.Parallel()
	if !matches("domain", "  example.com  ", "domain", "\texample.com\n") {
		t.Error("matches should trim whitespace")
	}
}

func TestMatches_MalformedCIDRRejects(t *testing.T) {
	t.Parallel()
	if matches("cidr", "not-a-cidr", "ip", "10.0.0.1") {
		t.Error("malformed CIDR should reject, not panic")
	}
}

func TestMatches_NonIPAgainstCIDR(t *testing.T) {
	t.Parallel()
	if matches("cidr", "10.0.0.0/8", "ip", "not-an-ip") {
		t.Error("non-IP target against CIDR scope should reject")
	}
}

func TestMatches_IPv6CIDR(t *testing.T) {
	t.Parallel()
	if !matches("cidr", "2001:db8::/32", "ip", "2001:db8::1") {
		t.Error("IPv6 inside CIDR should match")
	}
	if matches("cidr", "2001:db8::/32", "ip", "2002:db8::1") {
		t.Error("IPv6 outside CIDR should not match")
	}
}

func TestMatches_DefaultScopeTypeIsExactMatch(t *testing.T) {
	t.Parallel()
	if !matches("unknown-type", "abc", "x", "abc") {
		t.Error("unknown scope type should fall back to exact match")
	}
	if matches("unknown-type", "abc", "x", "abd") {
		t.Error("default branch should reject non-equal values")
	}
}
