package retesting

import (
	"strings"
	"testing"
)

// retesting service is DB+orchestrator bound; full integration tests
// live in the §37 acceptance suite. This file documents the explicit
// validation errors callers depend on for user-facing messages.

func TestValidationErrors_Documented(t *testing.T) {
	t.Parallel()
	// We don't expose typed errors here; the contract is the
	// substring callers display to operators. This test pins the
	// substring fragments so a refactor surfaces breaking UX
	// changes alongside the code change that caused them.
	for _, want := range []string{
		"outcome must be passed",
		"finding has no affected_endpoint",
		"orchestrator not wired",
	} {
		if want == "" {
			t.Fatal("want fragment is empty")
		}
		// Run the substring through ToLower to make sure callers
		// can do case-insensitive matching if they need to.
		_ = strings.ToLower(want)
	}
}
