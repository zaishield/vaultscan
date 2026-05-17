package scanorch

import "testing"

// detectTargetType is the dispatcher that decides which scope-guard
// branch a target falls under. A regression here changes which
// rules apply at submit time — i.e. a CIDR could be evaluated as
// a domain and slip past a CIDR-only allow-list.

func TestDetectTargetType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"https://api.example.com", "url"},
		{"http://x.y", "url"},
		{"example.com", "domain"},
		{"api.foo.example.com", "domain"},
		{"10.0.0.0/8", "cidr"},
		{"172.16.0.0/24", "cidr"},
		{"10.5.6.7", "ip"},
		{"192.0.2.1", "ip"},
	}
	for _, c := range cases {
		got := detectTargetType(c.in)
		if got != c.want {
			t.Errorf("detectTargetType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsIP(t *testing.T) {
	t.Parallel()
	if !isIP("10.0.0.1") {
		t.Error("10.0.0.1 should be IP")
	}
	if isIP("not-an-ip") {
		t.Error("non-IP should reject")
	}
	if isIP("10.0.0.0/8") {
		t.Error("CIDR should not be IP")
	}
	// Edge: an IPv4 with too few or too many dots.
	if isIP("10.0.0") {
		t.Error("3-dot-but-less form should reject")
	}
}

func TestIsCIDR(t *testing.T) {
	t.Parallel()
	if !isCIDR("10.0.0.0/8") {
		t.Error("standard CIDR should match")
	}
	if isCIDR("10.0.0.0") {
		t.Error("missing /mask should not match")
	}
	if isCIDR("example.com/path") {
		t.Error("domain with / should not match (host part isn't IP-ish)")
	}
}

func TestHasURLScheme(t *testing.T) {
	t.Parallel()
	if !hasURLScheme("https://example.com") {
		t.Error("https URL should match")
	}
	if !hasURLScheme("http://example.com") {
		t.Error("http URL should match")
	}
	if hasURLScheme("example.com") {
		t.Error("bare domain should not match")
	}
	if hasURLScheme("ftp://example.com") {
		t.Error("non-http scheme should not match (URL = http/https only here)")
	}
	if hasURLScheme("http:/x") { // missing one slash
		t.Error("malformed scheme should not match")
	}
}

func TestSummarizeTargets(t *testing.T) {
	t.Parallel()
	if got := summarizeTargets(nil); got != "" {
		t.Errorf("nil → %q want empty", got)
	}
	if got := summarizeTargets([]string{"a.com"}); got != "a.com" {
		t.Errorf("single → %q", got)
	}
	if got := summarizeTargets([]string{"a.com", "b.com", "c.com"}); got != "a.com (+2 more)" {
		t.Errorf("multi → %q", got)
	}
}

func TestNullIfEmpty(t *testing.T) {
	t.Parallel()
	if got := nullIfEmpty(""); got != nil {
		t.Errorf("empty → %v want nil", got)
	}
	if got := nullIfEmpty("x"); got != "x" {
		t.Errorf("non-empty → %v", got)
	}
}

func TestCountDots(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"":                  0,
		"abc":               0,
		"a.b":               1,
		"10.0.0.1":          3,
		"sub.example.com":   2,
	}
	for in, want := range cases {
		if got := countDots(in); got != want {
			t.Errorf("countDots(%q) = %d want %d", in, got, want)
		}
	}
}

func TestAllDigitsOrDot(t *testing.T) {
	t.Parallel()
	if !allDigitsOrDot("10.0.0.1") {
		t.Error("ip should pass")
	}
	if !allDigitsOrDot("123") {
		t.Error("digits should pass")
	}
	if allDigitsOrDot("10.0.0.a") {
		t.Error("letter should reject")
	}
	if allDigitsOrDot("") {
		// empty technically passes the all-of-... loop; document this.
		t.Log("empty allDigitsOrDot returns true (vacuous truth) — caller filters via countDots")
	}
}

func TestBeforeSlash(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"10.0.0.0/8":     "10.0.0.0",
		"no-slash":       "no-slash",
		"/leading":       "",
		"trailing/":      "trailing",
	}
	for in, want := range cases {
		if got := beforeSlash(in); got != want {
			t.Errorf("beforeSlash(%q) = %q want %q", in, got, want)
		}
	}
}
