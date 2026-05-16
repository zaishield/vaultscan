package tenants

import (
	"errors"
	"testing"
)

// tenants is DB-bound; the live behaviour is covered by
// test/integration/services_coverage_test.go. This file documents
// the sentinel-error contract callers depend on.

func TestErrNotFound_StableMessage(t *testing.T) {
	t.Parallel()
	if ErrNotFound == nil {
		t.Fatal("ErrNotFound is nil")
	}
	if msg := ErrNotFound.Error(); msg != "tenant not found" {
		t.Errorf("error message=%q want %q (callers compare exact text in logs)", msg, "tenant not found")
	}
	// errors.Is plumbing must keep working when the value is wrapped.
	wrapped := errors.Join(ErrNotFound, errors.New("context"))
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("errors.Is on wrapped ErrNotFound must match")
	}
}
