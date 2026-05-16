package middleware

import (
	"context"
	"strconv"
	"testing"
)

// In-memory limiter sits on every public route. A regression here
// shows up as latency added to every request, including health probes.
// This benchmark exercises the lock-and-refill path with a single hot
// key and the more realistic many-keys path that represents many
// tenants firing in parallel.
func BenchmarkInMemoryLimiter_HotKey(b *testing.B) {
	l := NewInMemoryLimiter()
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = l.Allow(ctx, "tenant-A", 1_000_000_000, 60)
	}
}

func BenchmarkInMemoryLimiter_ManyKeys(b *testing.B) {
	l := NewInMemoryLimiter()
	ctx := context.Background()
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = "tenant-" + strconv.Itoa(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = l.Allow(ctx, keys[i%len(keys)], 1_000_000_000, 60)
	}
}

func BenchmarkInMemoryLimiter_Parallel(b *testing.B) {
	l := NewInMemoryLimiter()
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			_, _ = l.Allow(ctx, "k-"+strconv.Itoa(i&127), 1_000_000_000, 60)
		}
	})
}
