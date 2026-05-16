package envmode

import "testing"

// Production-mode predicate must accept the same set in every caller
// (cmd/agent-gateway, internal/scanner, internal/config). This table
// is the authoritative spec — adding a new value here is the one
// place to extend.
func TestIsProduction(t *testing.T) {
	cases := map[string]bool{
		"production":   true,
		"PRODUCTION":   true,
		"Production":   true,
		"prod":         true,
		"PROD":         true,
		"  prod  ":     true,
		"\tproduction": true,
		"development":  false,
		"staging":      false,
		"":             false,
		"prod-staging": false,
		"productionx":  false,
	}
	for in, want := range cases {
		if got := IsProduction(in); got != want {
			t.Errorf("IsProduction(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("VAULTSCAN_ENV", "production")
	if !FromEnv() {
		t.Error("VAULTSCAN_ENV=production must return true")
	}
	t.Setenv("VAULTSCAN_ENV", "development")
	if FromEnv() {
		t.Error("VAULTSCAN_ENV=development must return false")
	}
	t.Setenv("VAULTSCAN_ENV", "")
	if FromEnv() {
		t.Error("empty env must return false")
	}
}
