// ssrf_guard.go — HTTP client guard against Server-Side Request
// Forgery (SSRF) via attacker-controlled integration URLs.
//
// Threat model: an operator with `manage_integrations` permission
// can set an integration's outbound URL. Without this guard, that
// URL goes straight to http.NewRequestWithContext + s.client.Do,
// allowing the operator to make the cluster speak to:
//
//   * 169.254.169.254 — cloud metadata service (AWS / GCP / Azure
//     IMDS; on AWS this returns IAM role creds)
//   * 127.0.0.0/8 — services bound to localhost in the API pod
//   * 10.0.0.0/8 + 172.16/12 + 192.168/16 — internal cluster services
//     (Postgres, Redis, OpenSearch, Keycloak, OpenBao admin APIs)
//   * 169.254.170.2 — ECS task metadata endpoint
//   * ::1, fc00::/7 — IPv6 loopback + ULA
//   * fe80::/10 — IPv6 link-local
//
// Defense:
//   1. URL scheme allowlist (https; http only when an env override
//      explicitly permits — needed for self-hosted dev installs).
//   2. Resolve the URL's host at dispatch time + reject if ANY
//      resolved IP is in a blocked range (DNS rebinding-safe).
//   3. Use a custom net.Dialer.Control that re-checks the IP a
//      second time when the TCP connect happens — closes the
//      time-of-check / time-of-use gap.
//
// Operator override: VAULTSCAN_INTEGRATION_ALLOW_PRIVATE_HOSTS=true
// disables the guard. Documented as a footgun in the security
// runbook; not enabled in any production overlay.

package integrations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// ErrSSRFBlocked is returned when an integration URL points at a
// disallowed host (loopback, private, link-local, metadata service).
// The handler maps this to HTTP 400 with a clear error so the
// operator knows to use a public endpoint.
var ErrSSRFBlocked = errors.New("integrations: target URL resolves to a disallowed host (SSRF guard)")

// blockedCIDRs holds the IP ranges the guard refuses to connect to.
// Source: IANA + cloud metadata documentation.
var blockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",         // "this network"
		"10.0.0.0/8",        // RFC1918
		"100.64.0.0/10",     // RFC6598 carrier-grade NAT
		"127.0.0.0/8",       // loopback
		"169.254.0.0/16",    // link-local, INCLUDES 169.254.169.254 (cloud IMDS)
		"172.16.0.0/12",     // RFC1918
		"192.0.0.0/24",      // IETF protocol assignments
		"192.0.2.0/24",      // TEST-NET-1
		"192.168.0.0/16",    // RFC1918
		"198.18.0.0/15",     // benchmarking
		"198.51.100.0/24",   // TEST-NET-2
		"203.0.113.0/24",    // TEST-NET-3
		"224.0.0.0/4",       // multicast
		"240.0.0.0/4",       // future-reserved (incl. broadcast)
		// IPv6
		"::1/128",           // loopback
		"::/128",            // unspecified
		"fc00::/7",          // unique-local
		"fe80::/10",         // link-local
		"ff00::/8",          // multicast
		// NOTE: ::ffff:0:0/96 (IPv4-mapped IPv6) is intentionally
		// NOT listed — that CIDR matches EVERY IPv4 address because
		// Go's net.IP stores 4-byte IPv4 in the 16-byte form. The
		// IPv4 CIDRs above already cover the actually-bad ranges
		// (loopback, RFC1918, link-local) and net.IPNet.Contains
		// transparently handles the v4-mapped form when checking
		// against a v4 CIDR.
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// guardDisabled is the operator override. Cached after first read
// to avoid re-stat'ing env on every request.
var guardDisabled = os.Getenv("VAULTSCAN_INTEGRATION_ALLOW_PRIVATE_HOSTS") == "true"

// SSRFGuardEnabled reports whether the SSRF guard is active. Test
// hooks use this to assert the right defaults are applied.
func SSRFGuardEnabled() bool { return !guardDisabled }

// SetGuardDisabledForTesting is a test-only override. Integration
// tests stand up httptest.NewServer on 127.0.0.1 which the guard
// would otherwise refuse to dispatch to. TestMain flips this on;
// production code MUST NOT call it.
func SetGuardDisabledForTesting(disabled bool) { guardDisabled = disabled }

// validateOutboundURL parses + sanity-checks the URL. Returns the
// resolved IPs so the caller can re-verify at dial time. Refuses
// unsupported schemes, malformed URLs, and pre-resolves the host
// to reject blocked targets.
func validateOutboundURL(target string) ([]net.IP, error) {
	if guardDisabled {
		return nil, nil
	}
	if target == "" {
		return nil, errors.New("integrations: empty URL")
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("integrations: parse URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// http allowed but logged via the caller's audit trail. Most
		// production integrations should be https; bare http is for
		// in-VPC test cases. If you need to forbid http entirely,
		// reject here.
	default:
		return nil, fmt.Errorf("%w: scheme=%q (only http+https allowed)", ErrSSRFBlocked, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("integrations: URL missing host")
	}
	// Reject hostname that is literally a metadata-service alias.
	// Cloud providers expose human-readable aliases in addition to
	// the raw IP.
	lower := strings.ToLower(host)
	for _, bad := range []string{
		"metadata.google.internal",
		"metadata",                   // some k8s setups resolve this
		"ec2.internal",
		"compute.internal",
	} {
		if lower == bad {
			return nil, fmt.Errorf("%w: blocked metadata alias %q", ErrSSRFBlocked, host)
		}
	}
	// Resolve. We pin a tight deadline so a malicious DNS server
	// can't stall the request.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("integrations: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IPs resolved for %q", ErrSSRFBlocked, host)
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if isBlocked(ip.IP) {
			return nil, fmt.Errorf("%w: %q resolves to blocked address %s", ErrSSRFBlocked, host, ip.IP)
		}
		out = append(out, ip.IP)
	}
	return out, nil
}

// isBlocked checks whether ip falls in any of blockedCIDRs.
//
// IPv4-in-v6 handling: if ip is an IPv4-mapped IPv6 address (e.g.
// "::ffff:127.0.0.1"), we unwrap to the underlying IPv4 first so
// the v4 CIDR list catches it. Without this an attacker could
// bypass the loopback check by encoding the literal as v6-mapped.
func isBlocked(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range blockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// newSafeTransport builds an http.Transport whose dialer re-checks
// every connection attempt's destination IP at TCP-connect time.
// Closes the DNS-rebinding gap that a naive pre-resolve would leave
// open (resolver returns 1.2.3.4, dial gets a refreshed answer of
// 169.254.169.254).
func newSafeTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlGuard,
	}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// controlGuard fires on every new TCP connection attempt; address
// holds the post-resolution "host:port" with the actual IP.
// Rejects via syscall.ECONNREFUSED so callers see a clean dial
// error rather than a hung connection.
func controlGuard(network, address string, _ syscall.RawConn) error {
	if guardDisabled {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Not a literal IP — this shouldn't happen because Go resolves
		// before invoking Control, but guard against future changes.
		return nil
	}
	if isBlocked(ip) {
		return fmt.Errorf("%w: dial to %s blocked", ErrSSRFBlocked, ip)
	}
	return nil
}
