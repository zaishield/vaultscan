// fleet_metrics.go — agent-gateway endpoint that emits Prometheus-
// format text aggregating per-agent telemetry from the DB.
//
// Closes the SEV-3 agent telemetry gap: instead of asking every agent
// to expose /metrics directly (which would require Prometheus to
// reach into customer networks — security non-starter), we serve a
// single federation endpoint at the gateway that exposes fleet
// state. Prometheus scrapes one URL no matter the fleet size.
//
// Mounted at:
//   GET /agent-fleet-metrics       text/plain; version=0.0.4
//
// Auth: same as the gateway's other ops endpoints (configurable;
// default = network-policy + scrape-target allow-listed inside the
// cluster, no per-request auth).
//
// Metrics emitted:
//   vaultscan_agent_status{agent_id, tenant_id, region, status} 0|1
//   vaultscan_agent_last_heartbeat_seconds{agent_id, tenant_id} <unix>
//   vaultscan_agent_cpu_percent{agent_id, tenant_id, kind="avg|peak"} N
//   vaultscan_agent_memory_percent{agent_id, tenant_id, kind="avg|peak"} N
//   vaultscan_agent_queue_depth{agent_id, tenant_id} N
//   vaultscan_agent_telemetry_samples{agent_id, tenant_id} N
//   vaultscan_agent_fleet_size{tenant_id, status} N
//   vaultscan_agent_emergency_stop_pending{agent_id, tenant_id} 0|1

package agentgw

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FleetMetrics serves the aggregated /agent-fleet-metrics endpoint.
// The DB pool is the only injection — every metric is a SQL query
// against the existing agents + agent_telemetry_rollups tables.
type FleetMetrics struct {
	pool *pgxpool.Pool
	// MaxAgents caps how many agents we emit per scrape so a 100k
	// fleet doesn't OOM Prometheus. Defaults to 5000; ops alert on
	// agents-omitted via vaultscan_agent_fleet_metrics_truncated.
	MaxAgents int
}

func NewFleetMetrics(pool *pgxpool.Pool) *FleetMetrics {
	return &FleetMetrics{pool: pool, MaxAgents: 5000}
}

// ScrapeToken, when non-empty, gates Handler() behind a bearer-token
// check. Set this from cmd/agent-gateway to the value of an env var
// (VAULTSCAN_FLEET_METRICS_SCRAPE_TOKEN). When unset, the endpoint
// is unauthenticated and relies entirely on NetworkPolicy isolation.
// Operators who want defense-in-depth (e.g. shared ingress) set
// the env var.
type fleetScrapeAuth struct {
	token string
}

var fleetScrapeAuthCfg fleetScrapeAuth

// SetScrapeToken configures the optional bearer-token gate. Called
// once at process boot. Empty string keeps the endpoint open
// (NetworkPolicy-only); non-empty requires Authorization: Bearer <t>.
func SetScrapeToken(t string) { fleetScrapeAuthCfg.token = t }

// Handler returns the http.HandlerFunc that emits the exposition.
// Mount at /agent-fleet-metrics from cmd/agent-gateway/main.go.
func (f *FleetMetrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if t := fleetScrapeAuthCfg.token; t != "" {
			got := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if len(got) < len(prefix) || got[:len(prefix)] != prefix || got[len(prefix):] != t {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		// Cap render time so a slow query doesn't pile up scrape
		// timeouts; Prometheus default scrape timeout is 10s.
		ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := f.write(ctx, w); err != nil {
			// Best-effort error footer so a partial scrape is still
			// usable; Prometheus parses up to the first malformed line.
			fmt.Fprintf(w, "# error: %s\n", escapeHelp(err.Error()))
		}
	}
}

func (f *FleetMetrics) write(ctx context.Context, w io.Writer) error {
	if err := f.writeFleetSize(ctx, w); err != nil {
		return err
	}
	if err := f.writeAgentRows(ctx, w); err != nil {
		return err
	}
	if err := f.writeEmergencyStopPending(ctx, w); err != nil {
		return err
	}
	return nil
}

// writeFleetSize emits aggregate counts per (tenant_id, status).
// Single GROUP BY so even a huge fleet emits ≤ tenants × statuses
// time series here.
func (f *FleetMetrics) writeFleetSize(ctx context.Context, w io.Writer) error {
	fmt.Fprintln(w, "# HELP vaultscan_agent_fleet_size Number of agents grouped by tenant and status.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_fleet_size gauge")
	rows, err := f.pool.Query(ctx, `
		SELECT COALESCE(tenant_id::text, ''), status, count(*)
		  FROM agents
		 GROUP BY tenant_id, status`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tenant, status string
		var n int
		if err := rows.Scan(&tenant, &status, &n); err != nil {
			return err
		}
		fmt.Fprintf(w, "vaultscan_agent_fleet_size{tenant_id=%q,status=%q} %d\n",
			tenant, status, n)
	}
	return rows.Err()
}

// writeAgentRows emits one set of per-agent metrics. The latest
// rollup row per agent (if any) supplies CPU/mem/queue figures;
// agents without a rollup emit only status + last_heartbeat.
func (f *FleetMetrics) writeAgentRows(ctx context.Context, w io.Writer) error {
	fmt.Fprintln(w, "# HELP vaultscan_agent_status 1 if agent is in given status, 0 otherwise.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_status gauge")
	fmt.Fprintln(w, "# HELP vaultscan_agent_last_heartbeat_seconds Unix timestamp of the agent's most recent heartbeat.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_last_heartbeat_seconds gauge")
	fmt.Fprintln(w, "# HELP vaultscan_agent_cpu_percent CPU percent reported by the agent in its most recent rollup window.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_cpu_percent gauge")
	fmt.Fprintln(w, "# HELP vaultscan_agent_memory_percent Memory percent reported by the agent.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_memory_percent gauge")
	fmt.Fprintln(w, "# HELP vaultscan_agent_queue_depth In-flight job queue depth at the agent.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_queue_depth gauge")
	fmt.Fprintln(w, "# HELP vaultscan_agent_telemetry_samples Number of heartbeat samples in the latest rollup window.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_telemetry_samples gauge")

	rows, err := f.pool.Query(ctx, `
		SELECT a.id::text,
		       COALESCE(a.tenant_id::text, ''),
		       COALESCE(a.region, ''),
		       a.status,
		       COALESCE(EXTRACT(EPOCH FROM a.last_heartbeat)::bigint, 0),
		       COALESCE(t.cpu_avg, 0),  COALESCE(t.cpu_peak, 0),
		       COALESCE(t.memory_avg, 0), COALESCE(t.memory_peak, 0),
		       COALESCE(t.queue_peak, 0),
		       COALESCE(t.samples, 0)
		  FROM agents a
		  LEFT JOIN LATERAL (
		    SELECT cpu_avg, cpu_peak, memory_avg, memory_peak,
		           queue_peak, samples
		      FROM agent_telemetry_rollups
		     WHERE agent_id = a.id
		     ORDER BY bucket_start DESC LIMIT 1
		  ) t ON true
		 ORDER BY a.id
		 LIMIT $1`, f.MaxAgents)
	if err != nil {
		return err
	}
	defer rows.Close()
	emitted := 0
	for rows.Next() {
		var (
			agentID, tenantID, region, status string
			lastHB                            int64
			cpuAvg, cpuPeak, memAvg, memPeak  float64
			queue, samples                    int
		)
		if err := rows.Scan(&agentID, &tenantID, &region, &status,
			&lastHB, &cpuAvg, &cpuPeak, &memAvg, &memPeak, &queue, &samples); err != nil {
			return err
		}
		emitted++
		// status is one-hot so PromQL `sum by(status)` works.
		for _, s := range []string{"online", "offline", "pending", "quarantined", "revoked", "degraded"} {
			v := 0
			if s == status {
				v = 1
			}
			fmt.Fprintf(w, "vaultscan_agent_status{agent_id=%q,tenant_id=%q,region=%q,status=%q} %d\n",
				agentID, tenantID, region, s, v)
		}
		fmt.Fprintf(w, "vaultscan_agent_last_heartbeat_seconds{agent_id=%q,tenant_id=%q} %d\n",
			agentID, tenantID, lastHB)
		fmt.Fprintf(w, "vaultscan_agent_cpu_percent{agent_id=%q,tenant_id=%q,kind=\"avg\"} %g\n",
			agentID, tenantID, cpuAvg)
		fmt.Fprintf(w, "vaultscan_agent_cpu_percent{agent_id=%q,tenant_id=%q,kind=\"peak\"} %g\n",
			agentID, tenantID, cpuPeak)
		fmt.Fprintf(w, "vaultscan_agent_memory_percent{agent_id=%q,tenant_id=%q,kind=\"avg\"} %g\n",
			agentID, tenantID, memAvg)
		fmt.Fprintf(w, "vaultscan_agent_memory_percent{agent_id=%q,tenant_id=%q,kind=\"peak\"} %g\n",
			agentID, tenantID, memPeak)
		fmt.Fprintf(w, "vaultscan_agent_queue_depth{agent_id=%q,tenant_id=%q} %d\n",
			agentID, tenantID, queue)
		fmt.Fprintf(w, "vaultscan_agent_telemetry_samples{agent_id=%q,tenant_id=%q} %d\n",
			agentID, tenantID, samples)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Surface truncation so ops alert on it (paginate if it fires).
	var totalAgents int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&totalAgents)
	truncated := 0
	if totalAgents > emitted {
		truncated = totalAgents - emitted
	}
	fmt.Fprintln(w, "# HELP vaultscan_agent_fleet_metrics_truncated Number of agents NOT emitted due to MaxAgents cap.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_fleet_metrics_truncated gauge")
	fmt.Fprintf(w, "vaultscan_agent_fleet_metrics_truncated %d\n", truncated)
	return nil
}

// writeEmergencyStopPending emits 1 per agent that has an unacked
// emergency stop. Aggregating to one bool per agent rather than
// counting events keeps cardinality bounded (1 series / agent at most).
func (f *FleetMetrics) writeEmergencyStopPending(ctx context.Context, w io.Writer) error {
	fmt.Fprintln(w, "# HELP vaultscan_agent_emergency_stop_pending 1 if the agent has an emergency stop awaiting ack.")
	fmt.Fprintln(w, "# TYPE vaultscan_agent_emergency_stop_pending gauge")
	rows, err := f.pool.Query(ctx, `
		SELECT a.id::text, COALESCE(a.tenant_id::text, ''),
		       CASE WHEN EXISTS (
		         SELECT 1 FROM agent_emergency_stops e
		          WHERE e.agent_id = a.id AND e.acked_at IS NULL
		       ) THEN 1 ELSE 0 END
		  FROM agents a
		 LIMIT $1`, f.MaxAgents)
	if err != nil {
		// Table absent on smaller deployments — emit zero rows; not fatal.
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var agentID, tenantID string
		var pending int
		if err := rows.Scan(&agentID, &tenantID, &pending); err != nil {
			return err
		}
		fmt.Fprintf(w, "vaultscan_agent_emergency_stop_pending{agent_id=%q,tenant_id=%q} %d\n",
			agentID, tenantID, pending)
	}
	return rows.Err()
}

// escapeHelp scrubs a string so it's safe inside a Prometheus HELP
// line (no newlines).
func escapeHelp(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
