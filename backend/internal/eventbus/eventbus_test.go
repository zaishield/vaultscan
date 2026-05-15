package eventbus

import "testing"

// Blueprint §22.1 enumerates exactly 21 canonical event types.
func TestAllEventTypesCount(t *testing.T) {
	if got := len(AllEventTypes()); got != 21 {
		t.Fatalf("event bus must expose 21 canonical types per Blueprint §22.1; got %d", got)
	}
}
