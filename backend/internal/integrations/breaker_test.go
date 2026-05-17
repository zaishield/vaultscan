package integrations

import (
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/circuitbreaker"
)

// breakerFor caches one breaker per integration_id and must be
// safe under concurrent access. The hot path holds a read lock,
// then promotes to a write lock + re-checks under it. These tests
// exercise that protocol without touching the DB-backed Service.

func TestBreakerFor_CachesPerIntegration(t *testing.T) {
	s := &Service{
		breakers: make(map[uuid.UUID]*circuitbreaker.Breaker),
	}
	id := uuid.New()

	b1 := s.breakerFor(id, "slack-channel-1")
	b2 := s.breakerFor(id, "slack-channel-1")
	if b1 != b2 {
		t.Fatal("breakerFor returned a different breaker on second call — cache missed")
	}
}

func TestBreakerFor_DistinctPerIntegration(t *testing.T) {
	s := &Service{
		breakers: make(map[uuid.UUID]*circuitbreaker.Breaker),
	}
	id1, id2 := uuid.New(), uuid.New()

	b1 := s.breakerFor(id1, "a")
	b2 := s.breakerFor(id2, "b")
	if b1 == b2 {
		t.Fatal("two distinct integration IDs should produce distinct breakers")
	}
}

// TestBreakerFor_ConcurrentLazyInit fires N goroutines all racing to
// create the same breaker; the post-read-lock check must coalesce
// them to a single instance.
func TestBreakerFor_ConcurrentLazyInit(t *testing.T) {
	s := &Service{
		breakers: make(map[uuid.UUID]*circuitbreaker.Breaker),
	}
	id := uuid.New()
	const n = 50

	got := make([]*circuitbreaker.Breaker, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			got[i] = s.breakerFor(id, "x")
		}()
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatalf("goroutine %d got a different breaker (lost the race coalescing)", i)
		}
	}
}
