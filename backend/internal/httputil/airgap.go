// airgap.go — global egress lockdown.
//
// VAULTSCAN_AIR_GAP=true forces every NewClient() instance to refuse
// outbound dials whose destination IP isn't on the operator-curated
// allowlist (VAULTSCAN_AIR_GAP_EGRESS_ALLOWLIST). The intended
// deployment is a closed network where the platform talks ONLY to
// the explicitly-named managed services (DB, object store, IdP) and
// nothing else — no Sigstore, no Rekor, no SaaS integration target,
// no cloud-posture API, no SMTP relay outside the allowlist.
//
// Why this exists separately from the SSRF guard:
//   - SSRF guard (internal/integrations/ssrf_guard.go) BLOCKS private
//     and metadata CIDRs to stop user-influenced URLs reaching them.
//     It is on by default and operator-disable-able.
//   - Air-gap mode does the OPPOSITE: it blocks PUBLIC space and
//     allowlists ONLY the operator-named CIDRs. It is off by default
//     and operator-enable-able.
//   - Together: SSRF guard runs on integration-target dials,
//     air-gap runs on EVERY outbound dial.
//
// Wiring: httputil.NewClient consults airgap.Enabled() at construction
// time and, if on, installs the airgap dial control on the transport.
// A caller that misses NewClient (raw http.Transport / DefaultClient)
// is NOT air-gapped — that's intentional; production guards enforce
// "use NewClient" via lint (golangci-lint forbidigo rule).

package httputil

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
)

var (
	airgapOnce   sync.Once
	airgapState  airgapConfig
)

type airgapConfig struct {
	enabled  bool
	allowed  []*net.IPNet
	allowedHosts map[string]bool // operator-named hostnames whose
	                             // resolution we ALSO want gated by
	                             // the allowlist; in practice they
	                             // must resolve to an allowed CIDR
	                             // OR be on this list explicitly.
}

// AirGapEnabled reports whether VAULTSCAN_AIR_GAP=true was set at boot.
// Cached on first call.
func AirGapEnabled() bool {
	loadAirGap()
	return airgapState.enabled
}

// AirGapAllowedCIDRs returns the parsed CIDR allowlist. Returned as
// strings for log output / health-check display.
func AirGapAllowedCIDRs() []string {
	loadAirGap()
	out := make([]string, 0, len(airgapState.allowed))
	for _, n := range airgapState.allowed {
		out = append(out, n.String())
	}
	return out
}

func loadAirGap() {
	airgapOnce.Do(func() {
		airgapState.enabled = strings.EqualFold(os.Getenv("VAULTSCAN_AIR_GAP"), "true")
		if !airgapState.enabled {
			return
		}
		raw := os.Getenv("VAULTSCAN_AIR_GAP_EGRESS_ALLOWLIST")
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			// Bare-IP convenience: convert to /32 (or /128 for v6).
			if !strings.Contains(item, "/") {
				if ip := net.ParseIP(item); ip != nil {
					if ip.To4() != nil {
						item = item + "/32"
					} else {
						item = item + "/128"
					}
				}
			}
			if _, n, err := net.ParseCIDR(item); err == nil {
				airgapState.allowed = append(airgapState.allowed, n)
			}
		}
	})
}

// airgapDialControl is the syscall.RawConn-aware hook the dialer
// uses to vet every concrete IP a connection lands on. If air-gap
// mode is OFF this is a no-op (the dialer doesn't even install it).
// If on and the address is outside the allowlist, the dial fails
// with a distinct error so operator logs can tell air-gap blocks
// apart from network failures.
func airgapDialControl(_ string, address string, _ syscall.RawConn) error {
	loadAirGap()
	if !airgapState.enabled {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("airgap: %w: cannot parse %q as IP", ErrAirGapBlocked, host)
	}
	for _, n := range airgapState.allowed {
		if n.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("airgap: %w: %s not in VAULTSCAN_AIR_GAP_EGRESS_ALLOWLIST", ErrAirGapBlocked, ip)
}

// ErrAirGapBlocked is returned (wrapped) when an outbound dial is
// rejected because air-gap mode is enabled and the destination IP
// isn't allowlisted. errors.Is(err, ErrAirGapBlocked) is how callers
// distinguish "air-gap dropped this" from "network is broken".
var ErrAirGapBlocked = errors.New("egress refused by air-gap policy")
