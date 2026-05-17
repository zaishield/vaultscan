package eventbus

import "testing"

// Blueprint §22.1 enumerated 21 canonical event types at launch.
// §8.7 (billing quotas) added 3 more in 2026-05, bringing the total
// to 24. Bump this if you add another canonical type.
func TestAllEventTypesCount(t *testing.T) {
	t.Parallel()
	const expected = 24
	if got := len(AllEventTypes()); got != expected {
		t.Fatalf("event bus must expose %d canonical types; got %d", expected, got)
	}
}
