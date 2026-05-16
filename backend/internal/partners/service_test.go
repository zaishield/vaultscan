package partners

import (
	"errors"
	"testing"
)

// The DB-bound logic in partners.Service is exercised by
// test/integration/partners_test.go against a live Postgres. This
// in-package file documents the sentinel error contract — any
// caller that switches on ErrNotFound expects this exact value, so a
// rename or re-wrapping is a breaking change.

func TestErrNotFound_IsExportedSentinel(t *testing.T) {
	t.Parallel()
	if ErrNotFound == nil {
		t.Fatal("ErrNotFound is nil")
	}
	if ErrNotFound.Error() != "partner not found" {
		t.Errorf("error message=%q want %q", ErrNotFound.Error(), "partner not found")
	}
	// Must be matchable via errors.Is for the standard pattern.
	wrapped := wrap(ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("wrapped ErrNotFound must be matchable via errors.Is")
	}
}

func wrap(err error) error {
	return errWrapper{err}
}

type errWrapper struct{ inner error }

func (e errWrapper) Error() string { return "wrap: " + e.inner.Error() }
func (e errWrapper) Unwrap() error { return e.inner }
