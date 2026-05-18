package integrations

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// isBlocked: catch each documented bad CIDR.
func TestIsBlocked_KnownBadRanges(t *testing.T) {
	t.Parallel()
	bad := []string{
		"127.0.0.1",            // loopback
		"127.255.255.254",      // loopback
		"169.254.169.254",      // AWS / GCP IMDS
		"169.254.170.2",        // ECS task metadata
		"10.0.0.1", "10.255.255.255", // RFC1918
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.254",
		"100.64.0.1",           // CGN
		"0.0.0.0",
		"224.0.0.1",            // multicast
		"::1",                  // v6 loopback
		"fe80::1",              // v6 link-local
		"fc00::1",              // v6 ULA
		"::ffff:127.0.0.1",     // IPv4-mapped IPv6 loopback
	}
	for _, s := range bad {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Errorf("parse %s", s)
			continue
		}
		if !isBlocked(ip) {
			t.Errorf("%s: expected BLOCKED, got allowed", s)
		}
	}
}

func TestIsBlocked_AllowsPublic(t *testing.T) {
	t.Parallel()
	good := []string{
		"1.1.1.1",       // Cloudflare DNS
		"8.8.8.8",       // Google DNS
		"140.82.121.4",  // github.com
		"2606:4700::1",  // Cloudflare v6
	}
	for _, s := range good {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Errorf("parse %s", s)
			continue
		}
		if isBlocked(ip) {
			t.Errorf("%s: expected allowed, got BLOCKED", s)
		}
	}
}

// validateOutboundURL surfaces the right errors for misconfigured /
// malicious URLs without ever invoking the network for obvious wins.
func TestValidateOutboundURL_RejectsObviousBadInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		target string
		want   string // substring expected in the error
	}{
		{"empty",              "",                          "empty URL"},
		{"unparseable",        "://not-a-url",              "parse"},
		{"bad-scheme-gopher",  "gopher://x:70/",            "scheme"},
		{"bad-scheme-file",    "file:///etc/passwd",        "scheme"},
		{"bad-scheme-ftp",     "ftp://internal.example",    "scheme"},
		{"no-host",            "https://",                  "missing host"},
		{"gcp-metadata-alias", "http://metadata.google.internal/computeMetadata/v1/", "metadata alias"},
		{"k8s-metadata-alias", "http://metadata/computeMetadata/", "metadata alias"},
	}
	for _, c := range cases {
		_, err := validateOutboundURL(c.target)
		if err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
			t.Errorf("%s: error %q missing %q", c.name, err, c.want)
		}
	}
}

// validateOutboundURL with literal IP targets — no DNS, deterministic.
func TestValidateOutboundURL_RejectsBlockedLiterals(t *testing.T) {
	t.Parallel()
	cases := []string{
		"http://127.0.0.1:8080/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5:5432/",
		"http://[::1]:9200/",
		"https://[fe80::1]/",
	}
	for _, c := range cases {
		_, err := validateOutboundURL(c)
		if err == nil {
			t.Errorf("%s: expected ErrSSRFBlocked, got nil", c)
			continue
		}
		if !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("%s: expected ErrSSRFBlocked, got %v", c, err)
		}
	}
}

// Public-IP literals should pass the synchronous checks (the dialer-
// level guard is what actually proves connect-time safety in prod).
func TestValidateOutboundURL_AllowsPublicLiterals(t *testing.T) {
	t.Parallel()
	cases := []string{
		"https://1.1.1.1/",
		"https://example.com/",
		"http://github.com/",
	}
	for _, c := range cases {
		_, err := validateOutboundURL(c)
		if err != nil {
			// DNS may fail in CI sandboxes; that's a soft pass.
			if strings.Contains(err.Error(), "resolve") {
				continue
			}
			t.Errorf("%s: unexpected error: %v", c, err)
		}
	}
}

// SSRF guard is on by default; ensures we don't ship with it disabled.
func TestSSRFGuard_OnByDefault(t *testing.T) {
	if !SSRFGuardEnabled() {
		t.Fatal("SSRF guard MUST be enabled by default; check VAULTSCAN_INTEGRATION_ALLOW_PRIVATE_HOSTS")
	}
}
