package integrations

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"
)

// FuzzValidateOutboundURL exercises validateOutboundURL with mutated
// URL strings. The assertion is precise: a fuzz finding is a BUG
// only if the URL's parsed host resolves to an address that
// `isBlocked()` says should be blocked AND validateOutboundURL
// nonetheless returned nil. That tight assertion avoids the
// "looks suspicious therefore must be blocked" trap — `::2` parses
// as a valid IPv6 literal that is genuinely NOT in any of the
// blocklisted CIDRs, so the guard's acceptance is correct.
//
// Seed inputs are the known-bad URLs that ssrf_guard_test.go
// already enumerates. The fuzzer mutates around them; any
// mutation that hits a blocklisted IP yet passes validation is a
// real bypass.
//
// Run for longer during release rehearsal:
//   go test -fuzz=FuzzValidateOutboundURL -fuzztime=60s ./internal/integrations/
func FuzzValidateOutboundURL(f *testing.F) {
	seeds := []string{
		// loopback in various encodings
		"http://127.0.0.1/x",
		"http://localhost/x",
		"http://127.000.000.001/x",
		"http://[::1]/x",
		"http://[::ffff:127.0.0.1]/x",
		// RFC1918
		"http://10.0.0.1/x",
		"http://172.16.0.1/x",
		"http://192.168.0.1/x",
		// Cloud metadata
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/x",
		"http://metadata/x",
		"http://ec2.internal/x",
		// CGN + link-local
		"http://100.64.0.1/x",
		"http://[fe80::1]/x",
		"http://[fc00::1]/x",
		// scheme bypass attempts (must be rejected on scheme, not IP)
		"ftp://127.0.0.1/x",
		"gopher://127.0.0.1/x",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/plain,attack",
		// credential-stuffing
		"http://example.com@127.0.0.1/x",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	prev := guardDisabled
	guardDisabled = false
	f.Cleanup(func() { guardDisabled = prev })

	f.Fuzz(func(t *testing.T, target string) {
		if len(target) > 2048 {
			t.Skip()
		}

		// Compute the ground truth: does the URL parse, what is its
		// host, does it resolve, are any resolved IPs blocked?
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			// Unparseable → validateOutboundURL also rejects. Nothing
			// to assert; let validate's behaviour be whatever it is.
			return
		}
		host := u.Hostname()
		if host == "" {
			return
		}

		// Scheme: only http+https are accepted. validateOutboundURL
		// MUST reject any other scheme.
		switch u.Scheme {
		case "http", "https":
			// fall through to IP-based check
		default:
			if _, err := validateOutboundURL(target); err == nil {
				t.Fatalf("SCHEME BYPASS: %q (scheme=%s) passed validation", target, u.Scheme)
			}
			return
		}

		// Resolve the host with the same 3s budget the guard uses.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if lookupErr != nil || len(ips) == 0 {
			// Unresolvable → validate also fails; not a fuzz signal.
			return
		}

		// Is ANY resolved IP in a blocklist CIDR?
		blocked := false
		for _, ip := range ips {
			if isBlocked(ip.IP) {
				blocked = true
				break
			}
		}

		_, guardErr := validateOutboundURL(target)
		if blocked && guardErr == nil {
			t.Fatalf("SSRF GUARD ESCAPE: %q resolves to a blocklisted address but validation passed",
				target)
		}
	})
}
