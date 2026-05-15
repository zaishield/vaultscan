// Package cache is a tiny TTL+LRU in-process cache for hot read paths
// (HS-04). The dashboards summary endpoint, the branding bundle, the
// scan_profiles list, and the integration config map all qualify —
// they're read on every request, change at most a few times a day, and
// don't need cross-process consistency on the order of milliseconds.
//
// For cross-process invalidation, callers wrap a Set with a bus.Publish
// of a "cache.invalidate" event; the receiving processes call Delete.
package cache

import (
	"container/list"
	"sync"
	"time"
)

type entry[V any] struct {
	key       string
	value     V
	expiresAt time.Time
	elem      *list.Element
}

// LRU is a goroutine-safe LRU + TTL cache. Reads bump the recency; writes
// evict the least-recently-used row when capacity is hit.
type LRU[V any] struct {
	mu       sync.Mutex
	cap      int
	ttl      time.Duration
	items    map[string]*entry[V]
	order    *list.List

	// stats — read under mu
	hits   int64
	misses int64
	evicts int64
}

func New[V any](capacity int, ttl time.Duration) *LRU[V] {
	if capacity <= 0 {
		capacity = 1024
	}
	return &LRU[V]{
		cap:   capacity,
		ttl:   ttl,
		items: map[string]*entry[V]{},
		order: list.New(),
	}
}

// Get returns the value + whether it was present (and unexpired).
func (c *LRU[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero V
	e, ok := c.items[key]
	if !ok {
		c.misses++
		return zero, false
	}
	if c.ttl > 0 && time.Now().After(e.expiresAt) {
		c.removeLocked(e)
		c.misses++
		return zero, false
	}
	c.hits++
	c.order.MoveToFront(e.elem)
	return e.value, true
}

// Set inserts or updates the entry, evicting the LRU row if needed.
func (c *LRU[V]) Set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		e.value = value
		if c.ttl > 0 {
			e.expiresAt = time.Now().Add(c.ttl)
		}
		c.order.MoveToFront(e.elem)
		return
	}
	if len(c.items) >= c.cap {
		// evict from the back of the list
		back := c.order.Back()
		if back != nil {
			c.removeLocked(c.items[back.Value.(string)])
			c.evicts++
		}
	}
	e := &entry[V]{key: key, value: value}
	if c.ttl > 0 {
		e.expiresAt = time.Now().Add(c.ttl)
	}
	e.elem = c.order.PushFront(key)
	c.items[key] = e
}

// Delete removes the key if present.
func (c *LRU[V]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		c.removeLocked(e)
	}
}

func (c *LRU[V]) removeLocked(e *entry[V]) {
	c.order.Remove(e.elem)
	delete(c.items, e.key)
}

// Stats returns hits/misses/evicts for observability.
type Stats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
	Evicts int64 `json:"evicts"`
	Size   int   `json:"size"`
}

func (c *LRU[V]) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Hits: c.hits, Misses: c.misses, Evicts: c.evicts, Size: len(c.items)}
}
