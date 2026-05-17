package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

// stubLimiter counts Allow calls per key. Returns true until the
// per-key counter exceeds `limit`. Lets us verify the tenant
// middleware actually maps requests to the tenant scope (not the
// per-identity scope).
type stubLimiter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newStub() *stubLimiter { return &stubLimiter{counts: map[string]int{}} }
func (s *stubLimiter) Name() string { return "stub" }
func (s *stubLimiter) Allow(_ context.Context, key string, limit, _ int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key]++
	return s.counts[key] <= limit, nil
}

func TestTenantRateLimit_AppliesPerTenantKey(t *testing.T) {
	t.Parallel()
	stub := newStub()
	// 100 per-identity × 2 multiplier = 200 per-tenant.
	mw := NewTenantRateLimitMiddleware(stub, 100, 60, 2)
	tenantA := uuid.New()
	tenantB := uuid.New()

	send := func(tenant uuid.UUID, user uuid.UUID) int {
		t.Helper()
		req := httptest.NewRequest("GET", "/x", nil)
		id := &auth.Identity{UserID: user, TenantID: &tenant}
		req = req.WithContext(auth.ContextWithIdentity(req.Context(), id))
		rec := httptest.NewRecorder()
		mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)
		return rec.Result().StatusCode
	}

	// 200 requests from tenant A: all should pass.
	for i := 0; i < 200; i++ {
		if got := send(tenantA, uuid.New()); got != 200 {
			t.Fatalf("tenant A req %d got %d want 200", i, got)
		}
	}
	// 201st must trip the tenant cap.
	if got := send(tenantA, uuid.New()); got != 429 {
		t.Errorf("tenant A req 201 got %d want 429", got)
	}
	// Tenant B's bucket is independent — first request passes.
	if got := send(tenantB, uuid.New()); got != 200 {
		t.Errorf("tenant B first req got %d want 200 (independent bucket)", got)
	}

	// Verify stub saw tenant: keys, not user: keys.
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if _, ok := stub.counts["tenant:"+tenantA.String()]; !ok {
		t.Errorf("expected stub to record tenant key; saw: %v", stub.counts)
	}
}

func TestTenantRateLimit_DisabledWhenMultiplierZero(t *testing.T) {
	t.Parallel()
	stub := newStub()
	mw := NewTenantRateLimitMiddleware(stub, 100, 60, 0) // disabled
	tenant := uuid.New()
	for i := 0; i < 1000; i++ {
		req := httptest.NewRequest("GET", "/x", nil)
		id := &auth.Identity{UserID: uuid.New(), TenantID: &tenant}
		req = req.WithContext(auth.ContextWithIdentity(req.Context(), id))
		rec := httptest.NewRecorder()
		mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)
		if rec.Result().StatusCode != 200 {
			t.Fatalf("req %d got %d (disabled cap should never block)", i, rec.Result().StatusCode)
		}
	}
	if len(stub.counts) != 0 {
		t.Errorf("disabled middleware must NOT call the limiter; saw %d calls", len(stub.counts))
	}
}

func TestTenantRateLimit_PassesThroughPlatformAdmin(t *testing.T) {
	t.Parallel()
	stub := newStub()
	mw := NewTenantRateLimitMiddleware(stub, 100, 60, 2)
	// Platform admin: TenantID == nil
	req := httptest.NewRequest("GET", "/x", nil)
	id := &auth.Identity{UserID: uuid.New(), TenantID: nil}
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), id))
	rec := httptest.NewRecorder()
	mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	if rec.Result().StatusCode != 200 {
		t.Errorf("platform admin got %d; tenant cap should not apply", rec.Result().StatusCode)
	}
}
