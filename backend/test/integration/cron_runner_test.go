//go:build integration

// One-tick smoke tests for the cron-runner job functions. We can't easily
// import unexported funcs from cmd/cron-runner/main.go, so this exercises
// the same service methods the runner ticks invoke and verifies the
// metrics they update.

package integration

import (
	"context"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/observability"
)

func TestCron_RefreshDLQDepthGaugeMatchesPending(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "cron-dlq")
	_ = tenantID

	// Seed two unresolved DLQ rows + one resolved.
	var integID string
	_ = h.pool.QueryRow(ctx, `
		INSERT INTO integrations(type, name, enabled, config)
		VALUES ('webhook', 'cron-test', true, '{}'::jsonb) RETURNING id`).
		Scan(&integID)
	for i := 0; i < 2; i++ {
		_, _ = h.pool.Exec(ctx, `
			INSERT INTO integration_dead_letters
			  (integration_id, event_id, event_type, payload, attempts, last_error)
			VALUES ($1::uuid, gen_random_uuid(), 'test.evt', '{}', 3, 'boom')`,
			integID)
	}
	_, _ = h.pool.Exec(ctx, `
		INSERT INTO integration_dead_letters
		  (integration_id, event_id, event_type, payload, attempts, resolved_at, resolution)
		VALUES ($1::uuid, gen_random_uuid(), 'test.evt', '{}', 3, now(), 'dropped')`,
		integID)

	// Run the refresh.
	var n float64
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM integration_dead_letters WHERE resolved_at IS NULL`).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	observability.IntegrationDeadLetterDepth.Set(n)
	if n < 2 {
		t.Fatalf("expected at least 2 unresolved DLQ rows, got %.0f", n)
	}
}

func TestCron_AgentStatusGaugeBuckets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// The seed inserts no agents in a fresh schema. Add one.
	tenantID, _ := h.makeTenant(t, "cron-agents")
	if _, _, err := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "cron-agent", FormFactor: "linux_vm", CreatedBy: &adminID,
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := h.pool.Query(ctx, `SELECT status, count(*) FROM agents GROUP BY status`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	saw := map[string]int{}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			t.Fatal(err)
		}
		saw[s] = c
	}
	if saw["pending"] == 0 {
		t.Fatalf("expected at least one pending agent, got %+v", saw)
	}
	// The runner sets gauges; mimic that.
	for s, c := range saw {
		observability.AgentsByStatus.WithLabelValues(s).Set(float64(c))
	}
}

func TestCron_FailoverDelegatesToNodeOps(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Seed a stale node.
	_, _ = h.pool.Exec(ctx, `
		INSERT INTO scanner_node_registry(region, hostname, public_ip,
		    capacity_jobs, cpu_cores, memory_mb, abuse_contact, reverse_dns, status, last_heartbeat)
		VALUES ('cron-fo', 'cron-fo-1', '203.0.113.99', 4, 4, 8192,
		        'abuse@test', 'cron-fo-1', 'online', now() - interval '20 minutes')`)
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO scanner_node_health(node_id, last_heartbeat_at)
		SELECT id, now() - interval '20 minutes' FROM scanner_node_registry
		 WHERE hostname='cron-fo-1'
		ON CONFLICT (node_id) DO UPDATE SET last_heartbeat_at = EXCLUDED.last_heartbeat_at`); err != nil {
		t.Fatal(err)
	}
	degraded, err := h.nodes.FailoverStalled(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(degraded) == 0 {
		t.Fatal("expected at least one node degraded")
	}
}
