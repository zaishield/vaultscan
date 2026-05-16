package scopeguard

import "testing"

// Scope-match runs on every scan target before any tool spawns. Even a
// "no-op" benchmark here pins the cost of the typical CIDR / suffix
// match so a clever refactor that adds an allocation per call is
// caught in CI rather than discovered when a 10k-host scope check
// blows the latency budget.

func BenchmarkMatches_DomainSuffix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = matches("domain", "example.com", "url", "https://api.example.com/x?y=1")
	}
}

func BenchmarkMatches_CIDR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = matches("cidr", "10.0.0.0/8", "ip", "10.42.7.5")
	}
}

func BenchmarkMatches_ExactURL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = matches("url", "https://api.example.com/x", "url", "https://api.example.com/x")
	}
}

func BenchmarkHostFromURL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = hostFromURL("https://api.example.com:8443/path?query=1#frag")
	}
}
