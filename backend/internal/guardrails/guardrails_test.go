package guardrails

import (
	"strings"
	"testing"
)

// matchesCondition + hasFact + newToken are pure helpers driving the
// policy-evaluator. matchesCondition's behaviour with nil values is
// non-obvious (nil means "fact must be absent or nil") so it gets
// explicit per-case coverage.

func TestMatchesCondition_ExactMatch(t *testing.T) {
	t.Parallel()
	facts := map[string]any{"actor_id": "alice", "severity": "high"}
	if !matchesCondition(map[string]any{"actor_id": "alice"}, facts) {
		t.Error("single-key match must succeed")
	}
	if !matchesCondition(map[string]any{
		"actor_id": "alice", "severity": "high",
	}, facts) {
		t.Error("multi-key match must succeed")
	}
}

func TestMatchesCondition_ValueMismatch(t *testing.T) {
	t.Parallel()
	facts := map[string]any{"severity": "high"}
	if matchesCondition(map[string]any{"severity": "low"}, facts) {
		t.Error("value mismatch must fail")
	}
}

func TestMatchesCondition_NilValueMeansAbsent(t *testing.T) {
	t.Parallel()
	// Condition {actor_id: nil} → must match when facts have no actor_id
	if !matchesCondition(map[string]any{"actor_id": nil}, map[string]any{}) {
		t.Error("nil condition value should match absent fact")
	}
	// And also when actor_id is explicitly nil
	if !matchesCondition(map[string]any{"actor_id": nil}, map[string]any{"actor_id": nil}) {
		t.Error("nil condition value should match nil fact")
	}
	// But NOT when fact has a real value
	if matchesCondition(map[string]any{"actor_id": nil}, map[string]any{"actor_id": "alice"}) {
		t.Error("nil condition value must NOT match real-valued fact")
	}
}

func TestMatchesCondition_MissingFactRejected(t *testing.T) {
	t.Parallel()
	if matchesCondition(map[string]any{"severity": "high"}, map[string]any{}) {
		t.Error("required fact missing must fail")
	}
}

func TestMatchesCondition_CoercesViaFmt(t *testing.T) {
	t.Parallel()
	// fmt.Sprintf("%v", 7) == fmt.Sprintf("%v", 7.0) (well, "7" vs "7")
	// so int / float / string of the same digit coerce.
	if !matchesCondition(map[string]any{"n": 7}, map[string]any{"n": "7"}) {
		t.Error("int<->string coercion via fmt.Sprintf should match")
	}
}

func TestHasFact_PresenceSemantics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"missing", nil, false}, // tested separately
		{"explicit nil", nil, false},
		{"empty string", "", false},
		{"non-empty string", "x", true},
		{"true bool", true, true},
		{"false bool", false, false},
		{"int", 7, true},
		{"slice", []string{"x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := map[string]any{}
			if tc.name != "missing" {
				facts["k"] = tc.v
			}
			if got := hasFact(facts, "k"); got != tc.want {
				t.Errorf("hasFact(%v)=%v want %v", tc.v, got, tc.want)
			}
		})
	}
}

func TestNewToken_LengthAndEntropy(t *testing.T) {
	t.Parallel()
	a := newToken()
	b := newToken()
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Errorf("token length=%d want 64", len(a))
	}
	if a == b {
		t.Error("two tokens collided — entropy bug")
	}
	if strings.Trim(a, "0123456789abcdef") != "" {
		t.Errorf("token contains non-hex chars: %q", a)
	}
}

// FuzzMatchesCondition — facts come from arbitrary event payloads;
// must never panic regardless of types.
func FuzzMatchesCondition(f *testing.F) {
	f.Add("k", "v")
	f.Add("k", "")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, key, val string) {
		_ = matchesCondition(
			map[string]any{key: val},
			map[string]any{key: val, "x": 7})
	})
}
