// checks.go — out-of-the-box CheckFunc factories for the common
// production dependencies. Wire these from cmd/api/main.go via
// registry.Register("name", health.PostgresCheck(pool), false).
package health

import (
	"context"
	"fmt"
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

// AuditChainCheck samples the most recent `tail` audit rows via
// audit.Service.VerifyTail and reports degraded if the chain hash
// state has diverged. This is the immediate "is the audit chain
// healthy right now?" answer that /readyz needs. Full-history
// attestation is still the hourly VerifyDeep cron job.
//
// Designed as a constructor over a function value rather than a
// concrete audit.Service type so the health package does not have
// to import audit (which transitively imports observability and
// risks an import cycle). cmd/api binds the function at startup.
func AuditChainCheck(verifyTail func(ctx context.Context, tail int) (int64, error), tail int) CheckFunc {
	return func(ctx context.Context) (Status, string) {
		if verifyTail == nil {
			return StatusDown, "audit verifier not wired"
		}
		badID, err := verifyTail(ctx, tail)
		if err != nil {
			return StatusDown, "verify error: " + err.Error()
		}
		if badID != 0 {
			return StatusDown, fmt.Sprintf("chain break at audit_logs.id=%d", badID)
		}
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
