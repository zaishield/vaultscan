package runner

import (
	"context"
	"errors"
	"testing"
)

// Production agents must refuse to fabricate scanner output when the
// host binary is missing. This test exercises the
// ErrSyntheticForbidden path so a regression in the production gate
// surfaces in CI rather than the data plane.
func TestRunner_SyntheticForbidden_InProductionMode(t *testing.T) {
	t.Parallel()
	r := NewRunnerStrict()
	// Pick a tool guaranteed not to be installed in CI.
	out, err := r.Execute(context.Background(), "bloodhound",
		[]string{"target.example"}, 0, 0)
	if !errors.Is(err, ErrSyntheticForbidden) {
		t.Fatalf("expected ErrSyntheticForbidden, got err=%v out=%v", err, out)
	}
}

// In dev (AllowSynthetic=true) the same call MUST return synthetic
// output, not an error. Tests that an over-aggressive lockdown doesn't
// break the dev workflow.
func TestRunner_SyntheticAllowed_InDevMode(t *testing.T) {
	t.Parallel()
	r := New()
	r.AllowSynthetic = true
	out, err := r.Execute(context.Background(), "bloodhound",
		[]string{"target.example"}, 0, 0)
	if err != nil {
		t.Fatalf("dev runner must tolerate missing binary, got %v", err)
	}
	if len(out.Stdout) == 0 {
		t.Errorf("expected synthetic stdout, got empty")
	}
}

// AllowsSynthetic exposes the flag so the outer agent shell can
// double-check before forwarding output upstream — protects against
// an upstream layer that thinks it's strict but reads from a runner
// in dev mode.
func TestRunner_AllowsSynthetic_ReflectsFlag(t *testing.T) {
	t.Parallel()
	if NewRunnerStrict().AllowsSynthetic() {
		t.Error("strict runner reports AllowsSynthetic=true")
	}
	r := New()
	r.AllowSynthetic = true
	if !r.AllowsSynthetic() {
		t.Error("dev runner reports AllowsSynthetic=false")
	}
}
