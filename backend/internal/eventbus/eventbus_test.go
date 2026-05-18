package eventbus

import "testing"

// Blueprint §22.1 enumerated 21 canonical event types at launch.
// §8.7 (billing quotas) added 3 more in 2026-05, bringing the total
// to 24. Migration 0061 (external + internal plane GA) added 11
// more (SSO/SCIM/quarantine/migrate/plan-request/impersonation/
// billing-adjust), bringing the total to 35. Bump this when you
// add another canonical type.
func TestAllEventTypesCount(t *testing.T) {
	t.Parallel()
	const expected = 35
	if got := len(AllEventTypes()); got != expected {
		t.Fatalf("event bus must expose %d canonical types; got %d", expected, got)
	}
}
