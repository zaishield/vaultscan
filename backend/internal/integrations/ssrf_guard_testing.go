//go:build integration

// ssrf_guard_testing.go — test-only override for the SSRF guard.
// The `integration` build tag means this file is ONLY compiled when
// the integration test binary is built (`go test -tags=integration`).
// A production binary built without that tag will fail to link if
// any code tries to call SetGuardDisabledForTesting — by design.
//
// The override exists because httptest.NewServer binds 127.0.0.1,
// which the guard refuses to dispatch to. With the build-tag split
// in place, the only consumer is backend/test/integration/main_test.go.

package integrations

// SetGuardDisabledForTesting flips the guard on or off for the
// current process. Test-only. Production builds cannot call this
// because the file is excluded by the build tag.
func SetGuardDisabledForTesting(disabled bool) { guardDisabled = disabled }
