package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

// SupportedTypes is the source of truth for which integration
// providers we accept on Create. validType + contains underpin
// that gate; tests prevent a typo from silently disabling a
// supported provider.

func TestSupportedTypes_HasExpectedProviders(t *testing.T) {
	t.Parallel()
	got := SupportedTypes()
	// Locked by SupportedTypes — keep in sync if a new provider
	// lands. Test exists so renames surface here rather than
	// silently breaking the Create allow-list at runtime.
	want := []string{"jira", "servicenow", "slack", "teams", "webhook",
		"siem", "gitlab", "github", "jenkins", "sentinel"}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SupportedTypes missing %q", w)
		}
	}
}

func TestSupportedTypes_NoDuplicates(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, p := range SupportedTypes() {
		if seen[p] {
			t.Errorf("duplicate provider in SupportedTypes: %s", p)
		}
		seen[p] = true
	}
}

func TestValidType(t *testing.T) {
	t.Parallel()
	if !validType("jira") {
		t.Error("jira should be valid")
	}
	if validType("not-a-real-integration") {
		t.Error("unknown type should reject")
	}
	if validType("") {
		t.Error("empty type should reject")
	}
}

func TestContains(t *testing.T) {
	t.Parallel()
	xs := []string{"a", "b", "c"}
	if !contains(xs, "b") {
		t.Error("should find b")
	}
	if contains(xs, "d") {
		t.Error("should not find d")
	}
	if contains(nil, "a") {
		t.Error("nil slice should not contain anything")
	}
}

// integrationField whitelist — the latent-injection guard we added
// in the audit pass. Real exploits need a future caller passing
// user input, but the whitelist is what defends against that.

func TestAllowedIntegrationFields_AcceptsKnownFields(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"issue_type", "format", "name", "type", "endpoint"} {
		if !allowedIntegrationFields[f] {
			t.Errorf("whitelist missing legit field %q", f)
		}
	}
}

func TestAllowedIntegrationFields_RejectsInjectionAttempts(t *testing.T) {
	t.Parallel()
	for _, f := range []string{
		"name; DROP TABLE integrations",
		"name UNION SELECT password FROM users",
		"name)--",
		"*",
		"",
	} {
		if allowedIntegrationFields[f] {
			t.Errorf("whitelist must not allow injection attempt %q", f)
		}
	}
}

// jitterDuration scales d by a uniform random factor in [0.5, 1.5).
// Used by the delivery retry backoff to spread thundering-herd.
// Statistical test: across many samples, the average should land
// near d (with a wide tolerance — this is a probabilistic check,
// not exact).

func TestJitterDuration_StaysWithinBounds(t *testing.T) {
	t.Parallel()
	d := 100 * time.Millisecond
	for i := 0; i < 200; i++ {
		got := jitterDuration(d)
		if got < d/2 || got >= d*3/2 {
			t.Errorf("jitter[%d] = %v outside [%v, %v)", i, got, d/2, d*3/2)
		}
	}
}

func TestJitterDuration_ZeroPassesThrough(t *testing.T) {
	t.Parallel()
	if got := jitterDuration(0); got != 0 {
		t.Errorf("jitter(0) = %v want 0", got)
	}
}

func TestJitterDuration_NegativePassesThrough(t *testing.T) {
	t.Parallel()
	// Negative input is treated as the no-op case; matches the
	// guard inside jitterDuration.
	if got := jitterDuration(-time.Second); got >= 0 {
		t.Errorf("jitter(-1s) = %v should remain negative or zero", got)
	}
}

// nullIfEmpty / nullIfZero — the SQL NULL boundary.

func TestNullIfEmpty(t *testing.T) {
	t.Parallel()
	if nullIfEmpty("") != nil {
		t.Error(`"" → must be nil for SQL NULL`)
	}
	if got := nullIfEmpty("x"); got != "x" {
		t.Errorf("non-empty → %v", got)
	}
}

func TestNullIfZero(t *testing.T) {
	t.Parallel()
	if nullIfZero(0) != nil {
		t.Error("0 → must be nil")
	}
	if got := nullIfZero(42); got != 42 {
		t.Errorf("non-zero → %v", got)
	}
}

// hexDigest helper used by the HMAC signing path. Sanity-check
// against a hand-computed SHA-256.
func TestHexDigest_KnownVector(t *testing.T) {
	t.Parallel()
	h := hmac.New(sha256.New, []byte("key"))
	got := hexDigest(h, []byte("data"))
	// Known: HMAC-SHA256("key","data") = 5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0
	want := "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"
	if got != want {
		t.Errorf("hexDigest = %s, want %s", got, want)
	}
}
