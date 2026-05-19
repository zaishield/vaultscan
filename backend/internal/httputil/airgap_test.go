package httputil

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
)

// setAirgapStateForTest stubs the package-level state and short-
// circuits the sync.Once so loadAirGap() won't clobber the stub.
func setAirgapStateForTest(t *testing.T, cfg airgapConfig) {
	t.Helper()
	airgapOnce = sync.Once{}
	airgapOnce.Do(func() {}) // mark done with an empty closure
	airgapState = cfg
	t.Cleanup(func() {
		airgapOnce = sync.Once{}
		airgapState = airgapConfig{}
	})
}

// TestAirgapDialControl_BlocksUnlisted exercises the dial-control hook
// directly so we don't depend on a real TCP attempt for the unit test.
// The bigger story (NewClient installs the hook only when air-gap is
// on, hot-paths skip the hook when off) is covered by the integration
// path; here we just check the gate logic.
func TestAirgapDialControl_BlocksUnlisted(t *testing.T) {
	setAirgapStateForTest(t, airgapConfig{
		enabled: true,
		allowed: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
	})

	tests := []struct {
		addr  string
		blocked bool
	}{
		{"10.5.5.5:5432", false},
		{"169.254.169.254:80", true},
		{"1.2.3.4:443", true},
		{"203.0.113.7:443", true},
	}
	for _, tc := range tests {
		err := airgapDialControl("tcp", tc.addr, syscall.RawConn(nil))
		if tc.blocked && err == nil {
			t.Errorf("expected %q blocked, got nil", tc.addr)
		}
		if tc.blocked && err != nil && !errors.Is(err, ErrAirGapBlocked) {
			t.Errorf("expected ErrAirGapBlocked for %q, got %v", tc.addr, err)
		}
		if !tc.blocked && err != nil {
			t.Errorf("expected %q allowed, got %v", tc.addr, err)
		}
	}
}

func TestAirgapDialControl_NoopWhenOff(t *testing.T) {
	setAirgapStateForTest(t, airgapConfig{enabled: false})
	if err := airgapDialControl("tcp", "1.2.3.4:443", nil); err != nil {
		t.Fatalf("disabled airgap rejected dial: %v", err)
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}
