package cache

import (
	"strconv"
	"testing"
	"time"
)

func TestLRU_HitMissEvict(t *testing.T) {
	c := New[int](3, 0)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("get a: %v %v", v, ok)
	}
	// Inserting d should evict b (least-recently-used after the Get bumped a + c).
	c.Get("c")
	c.Set("d", 4)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	st := c.Stats()
	if st.Evicts != 1 {
		t.Fatalf("expected 1 eviction, got %d", st.Evicts)
	}
}

func TestLRU_TTLExpires(t *testing.T) {
	c := New[string](10, 10*time.Millisecond)
	c.Set("k", "v")
	if _, ok := c.Get("k"); !ok {
		t.Fatal("expected fresh entry to be present")
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected TTL expiry")
	}
}

func TestLRU_HitRate(t *testing.T) {
	c := New[int](100, 0)
	for i := 0; i < 100; i++ {
		c.Set(strconv.Itoa(i), i)
	}
	// 95 hits.
	for i := 0; i < 95; i++ {
		if _, ok := c.Get(strconv.Itoa(i)); !ok {
			t.Fatal("unexpected miss")
		}
	}
	// 5 misses.
	for i := 200; i < 205; i++ {
		if _, ok := c.Get(strconv.Itoa(i)); ok {
			t.Fatal("unexpected hit")
		}
	}
	st := c.Stats()
	if st.Hits != 95 || st.Misses != 5 {
		t.Fatalf("expected 95H/5M, got %dH/%dM", st.Hits, st.Misses)
	}
}
