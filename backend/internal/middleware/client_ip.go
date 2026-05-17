package middleware

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// TrustedProxyCIDRs is the set of upstream proxy networks whose
// X-Forwarded-For header we honour. Populated once at process start
// from VAULTSCAN_TRUSTED_PROXY_CIDRS (comma-separated CIDR list).
// Without a trust list the API treats the header as attacker-
// controlled and falls back to RemoteAddr.
//
// Why this matters: every IP-keyed control — audit attribution,
// rate-limiter buckets, brute-force lockouts, evidence access logs —
// uses whatever clientIP() returns. If we trust X-Forwarded-For
// unconditionally an attacker can poison rate-limiter buckets, evade
// brute-force lockout, and falsely attribute their actions to other
// users' IPs in the audit chain. Exposed in middleware so handlers
// in package api can share the same trust decision.
var TrustedProxyCIDRs = parseTrustedProxies(os.Getenv("VAULTSCAN_TRUSTED_PROXY_CIDRS"))

func parseTrustedProxies(spec string) []*net.IPNet {
	if spec == "" {
		return nil
	}
	out := []*net.IPNet{}
	for _, c := range strings.Split(spec, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		out = append(out, ipnet)
	}
	return out
}

// ClientIP resolves the request's effective source IP. If the
// immediate peer is in TrustedProxyCIDRs it returns the leftmost
// X-Forwarded-For entry; otherwise it returns the TCP peer address.
//
// This is the single source of truth — both middleware (rate limit)
// and handlers (audit, evidence access logs) call this to ensure they
// agree on what "the client" means for a given request.
func ClientIP(r *http.Request) net.IP {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote == nil || len(TrustedProxyCIDRs) == 0 {
		return remote
	}
	for _, cidr := range TrustedProxyCIDRs {
		if !cidr.Contains(remote) {
			continue
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			if i := strings.Index(v, ","); i >= 0 {
				v = v[:i]
			}
			if parsed := net.ParseIP(strings.TrimSpace(v)); parsed != nil {
				return parsed
			}
		}
		break
	}
	return remote
}
