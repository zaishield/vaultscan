// checks.go — out-of-the-box CheckFunc factories for the common
// production dependencies. Wire these from cmd/api/main.go via
// registry.Register("name", health.PostgresCheck(pool), false).
package health

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresCheck pings the pool. Mandatory in almost every deployment.
func PostgresCheck(pool *pgxpool.Pool) CheckFunc {
	return func(ctx context.Context) (Status, string) {
		if pool == nil {
			return StatusDown, "pool not configured"
		}
		if err := pool.Ping(ctx); err != nil {
			return StatusDown, "ping: " + err.Error()
		}
		s := pool.Stat()
		// Saturation isn't a hard fail but it IS visible — surface
		// it so ops doesn't need to cross-reference /metrics for
		// the same data during incident triage.
		if s.AcquiredConns() >= s.MaxConns()*9/10 {
			return StatusDegraded, "pool 90%+ saturated"
		}
		return StatusOK, ""
	}
}

// TCPCheck attempts a TCP dial to host:port. Generic enough to use
// for Redis, OpenSearch, NATS, OpenBao, etc. when full-protocol
// checks aren't worth the dependency.
func TCPCheck(addr string) CheckFunc {
	return func(ctx context.Context) (Status, string) {
		if addr == "" {
			return StatusDown, "addr not configured"
		}
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return StatusDown, err.Error()
		}
		_ = conn.Close()
		return StatusOK, ""
	}
}

// HTTPCheck performs an HTTP GET on url and treats <500 as healthy.
// Use for Keycloak (issuer + /.well-known), OpenSearch HEAD, etc.
func HTTPCheck(client *http.Client, url string) CheckFunc {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return func(ctx context.Context) (Status, string) {
		if url == "" {
			return StatusDown, "url not configured"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return StatusDown, err.Error()
		}
		resp, err := client.Do(req)
		if err != nil {
			return StatusDown, err.Error()
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			return StatusDown, "upstream " + resp.Status
		}
		return StatusOK, ""
	}
}
