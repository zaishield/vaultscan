package evidence

import (
	"errors"
	"os"
	"testing"
)

// TestNewVault_RefusesKnownDevKey is the boot-time safety net for
// the highest-impact misconfiguration we can ship: a real
// deployment whose master KEK still holds the dev-doc placeholder.
// Without the refusal, an operator who forgets to override
// VAULTSCAN_EVIDENCE_MASTER_KEY in their helm values would encrypt
// every tenant's evidence under a key that's in source control.
func TestNewVault_RefusesKnownDevKey(t *testing.T) {
	// Ensure the escape hatch is OFF for this test even if the
	// surrounding test binary's environment has it set.
	prev, had := os.LookupEnv("VAULTSCAN_ALLOW_DEV_KEYS")
	os.Unsetenv("VAULTSCAN_ALLOW_DEV_KEYS")
	t.Cleanup(func() {
		if had {
			os.Setenv("VAULTSCAN_ALLOW_DEV_KEYS", prev)
		}
	})

	for _, key := range knownDevMasterKeys {
		_, err := NewVault(nil, nil, nil, key)
		if !errors.Is(err, ErrDevKeyInProduction) {
			t.Errorf("known-dev key %q: expected ErrDevKeyInProduction, got %v", key, err)
		}
	}
}

// TestNewVault_AllowsDevKeyWithOptIn — the escape hatch works.
// The test harness uses this path; without it the integration
// suite couldn't boot.
func TestNewVault_AllowsDevKeyWithOptIn(t *testing.T) {
	prev, had := os.LookupEnv("VAULTSCAN_ALLOW_DEV_KEYS")
	os.Setenv("VAULTSCAN_ALLOW_DEV_KEYS", "true")
	t.Cleanup(func() {
		if had {
			os.Setenv("VAULTSCAN_ALLOW_DEV_KEYS", prev)
		} else {
			os.Unsetenv("VAULTSCAN_ALLOW_DEV_KEYS")
		}
	})

	// We expect NewVault to get past the dev-key check. It will
	// still fail later (nil pool / nil audit / nil bus) — we only
	// care that it doesn't return ErrDevKeyInProduction.
	for _, key := range knownDevMasterKeys {
		_, err := NewVault(nil, nil, nil, key)
		if errors.Is(err, ErrDevKeyInProduction) {
			t.Errorf("opt-in disabled by env: %v", err)
		}
	}
}

// TestNewVault_AcceptsProductionKey — a non-dev base64 key that
// decodes to 32 bytes is accepted (the rest of the constructor may
// fail on nil pool, that's fine — we only verify the dev-key gate
// does NOT trip on a legitimately-random key).
func TestNewVault_AcceptsProductionKey(t *testing.T) {
	prev, had := os.LookupEnv("VAULTSCAN_ALLOW_DEV_KEYS")
	os.Unsetenv("VAULTSCAN_ALLOW_DEV_KEYS")
	t.Cleanup(func() {
		if had {
			os.Setenv("VAULTSCAN_ALLOW_DEV_KEYS", prev)
		}
	})
	// 32-byte all-zero key encoded — distinct from the placeholder
	// "AAA..." pattern but the same prefix; pick something that's
	// not in the blocklist.
	prodKey := "ZG9udC11c2UtdGhpcy1pbi1wcm9kLWtleS1ub3QtcmVhbC0xMjMK" // dummy text
	_, err := NewVault(nil, nil, nil, prodKey)
	if errors.Is(err, ErrDevKeyInProduction) {
		t.Errorf("legitimate key tripped dev-key gate: %v", err)
	}
}
