package dashboards

import (
	"testing"

	"github.com/google/uuid"
)

// Dashboards pure helpers govern role-gated layout visibility and the
// live-stream tenant identity. Tested without DB.

func TestValidLayoutRole(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"executive":   true,
		"soc":         true,
		"risk":        true,
		"partner_msp": true,
		"scope_admin": true,
		"":            false,
		"admin":       false,
		"EXECUTIVE":   false,
		"customer":    false,
	}
	for in, want := range cases {
		if got := validLayoutRole(in); got != want {
			t.Errorf("validLayoutRole(%q)=%v want %v", in, got, want)
		}
	}
}

func TestTenantOrZero(t *testing.T) {
	t.Parallel()
	if got := tenantOrZero(nil); got != uuid.Nil {
		t.Errorf("nil → %v want %v", got, uuid.Nil)
	}
	id := uuid.New()
	if got := tenantOrZero(&id); got != id {
		t.Errorf("&id → %v want %v", got, id)
	}
}
