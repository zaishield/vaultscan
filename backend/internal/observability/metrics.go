// Package observability owns the metrics + tracing wiring. The
// /metrics endpoint is mounted by api.Mount; tracer-provider bootstrap
// is called from main.
package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Reg is the registry every package writes counters into. Exported so
// tests can pull metric values directly.
var Reg = prometheus.NewRegistry()

// All vaultscan_* metrics. Counters where appropriate, histograms for
// latency, gauges for queue depths.
var (
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_http_requests_total",
			Help: "HTTP requests by route, method, status_code.",
		},
		[]string{"route", "method", "status"},
	)
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "vaultscan_http_request_duration_seconds",
			Help:    "HTTP request duration by route + method.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"route", "method"},
	)
	AuthLoginFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_auth_login_failures_total",
		Help: "Login failures (any reason). HS-01 brute-force shield bumps a second counter.",
	})
	AuthIPLockouts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_auth_ip_lockouts_total",
		Help: "IP-level lockouts the brute-force shield has triggered.",
	})
	ScanJobsCreated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_scan_jobs_created_total",
			Help: "Scan jobs submitted by plane.",
		},
		[]string{"plane"},
	)
	ScanJobsCompleted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_scan_jobs_completed_total",
			Help: "Scan jobs terminal-stated.",
		},
		[]string{"plane", "status"}, // status: succeeded|failed|stopped
	)
	FindingsIngested = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_findings_ingested_total",
			Help: "Findings written to the DB, by scanner + severity.",
		},
		[]string{"scanner", "severity"},
	)
	FindingsDeduplicated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_findings_deduplicated_total",
		Help: "Re-ingests collapsed onto an existing finding.",
	})
	AuditChainBreaks = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_audit_chain_breaks_total",
		Help: "Audit-log hash-chain divergences detected.",
	})
	AgentsByStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vaultscan_agents_by_status",
			Help: "Agent count by status (online|offline|pending|quarantined).",
		},
		[]string{"status"},
	)
	IntegrationDeliveryFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_integration_delivery_failures_total",
			Help: "Outbound integration deliveries that hit non-2xx (per type).",
		},
		[]string{"integration_type"},
	)
	IntegrationDeadLetterDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vaultscan_integration_dead_letter_depth",
		Help: "Pending (unresolved) DLQ entries across all integrations.",
	})
	// Evidence-vault integrity counter. Incremented by the hourly
	// evidence_integrity_sample cron task each time a sampled blob
	// fails to round-trip (storage read + decrypt + sha256 match).
	// Any non-zero rate = a corruption-class incident; alert at
	// rate > 0 over 1h.
	EvidenceIntegrityFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_evidence_integrity_failures_total",
		Help: "Evidence blobs that failed round-trip verification during sample sweeps.",
	})
	// AESGCMSeals counts AES-GCM Seal calls labelled by key role
	// (master-kek | tenant-dek | jwk-wrap). 96-bit random nonces have
	// a birthday bound of ~2^32 calls per key before collision risk
	// gets non-negligible. With this metric, ops can alert when
	// per-key Seal count climbs into the 10^8 range — well before
	// danger — and rotate the key.
	//
	// Alert rule: sum by (role) (rate(vaultscan_aesgcm_seals_total[1h])) * 3600 * 24 * 365
	// exceeds 1e9 per-year → schedule rotation.
	AESGCMSeals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_aesgcm_seals_total",
			Help: "AES-GCM Seal invocations by key role. Track per-role call counts to detect approaching nonce birthday bound (~2^32 per key).",
		},
		[]string{"role"},
	)
	// AuditTSAFailures: count of audit-archive runs that proceeded
	// without an RFC 3161 timestamp because the TSA call failed.
	// A SOC2 auditor expects every archive run to carry a TSA token;
	// a non-zero rate over 1h is operator-actionable (DNS, cert,
	// rate limit, TSA outage).
	AuditTSAFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_audit_tsa_failures_total",
		Help: "Audit archive runs persisted without a TSA proof because the timestamp authority call failed.",
	})
	// NotifyQuarantine: count of notification messages routed to
	// 'quarantined' state because no transport was registered for
	// the message's `kind`. A non-zero rate signals a missing /
	// misnamed transport in the chart's notify.transports config.
	NotifyQuarantine = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_notify_quarantine_total",
			Help: "Notification messages quarantined because no transport is registered for their kind.",
		},
		[]string{"kind"},
	)
	// TenantPoolDowngrade: count of times IsolationRouter.PoolFor
	// fell back from a dedicated tenant pool to the shared platform
	// pool. A non-zero rate means a dedicated-tier tenant is
	// silently sharing isolation; operator should inspect
	// tenant_pool_routing.
	TenantPoolDowngrade = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_tenant_pool_downgrade_total",
			Help: "Dedicated tenants that fell back to the shared platform pool (by reason).",
		},
		[]string{"reason"},
	)
	// InboundHMACFailures: count of inbound webhook signature
	// verifications that failed, labelled by reason. A sustained
	// non-zero rate against a single integration is the classic
	// signature-probe signature; alert when it crosses 1/min.
	InboundHMACFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_inbound_hmac_failures_total",
			Help: "Inbound webhook signature verifications that failed (by reason code).",
		},
		[]string{"reason"},
	)
	EmergencyStopSLAms = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "vaultscan_emergency_stop_sla_ms",
		Help:    "Time from operator request to agent ack, in milliseconds.",
		Buckets: []float64{50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000},
	})
	WorkerTickDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "vaultscan_worker_tick_duration_seconds",
			Help:    "Background-worker job duration by name.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 30, 60, 300},
		},
		[]string{"job", "outcome"}, // outcome: ok | error
	)

	// Pool stats — populated by observability.StartPoolStatsExporter.
	// Operators alert on:
	//   * pool_acquired ≈ pool_max  → saturating; requests queueing
	//   * pool_waiting > 0 for >30s → hard saturation; bump MAX_CONNS
	//   * pool_idle == 0 for sustained periods → undersized pool
	DBPoolAcquired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vaultscan_db_pool_acquired",
		Help: "Number of connections currently checked out from the pool.",
	})
	DBPoolIdle = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vaultscan_db_pool_idle",
		Help: "Number of connections sitting idle in the pool.",
	})
	DBPoolWaiting = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vaultscan_db_pool_waiting",
		Help: "Number of goroutines currently blocked waiting for a connection.",
	})
	DBPoolMax = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vaultscan_db_pool_max",
		Help: "Configured MaxConns ceiling for the pool.",
	})
	DBPoolAcquireCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_db_pool_acquire_total",
		Help: "Cumulative successful pool acquisitions.",
	})
	DBPoolAcquireDuration = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_db_pool_acquire_wait_seconds_total",
		Help: "Cumulative wait time spent acquiring connections (s).",
	})
	DBPoolCanceledAcquires = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vaultscan_db_pool_acquire_canceled_total",
		Help: "Acquisitions that returned an error (ctx cancel, pool closed).",
	})

	// Rate-limit hits (per-identity OR per-tenant). Surfaces noisy
	// neighbors and tenant-level abuse separately so on-call can act.
	RateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_rate_limit_hits_total",
			Help: "Requests rejected by the rate limiter, by scope.",
		},
		[]string{"scope"}, // identity | tenant
	)

	// Idempotency-Key middleware metrics. replayed = the cached
	// response served from the store; missed = the key was new
	// (fresh request execution).
	IdempotencyHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vaultscan_idempotency_hits_total",
			Help: "Idempotency-Key lookups by outcome.",
		},
		[]string{"outcome"}, // replayed | new | conflict | inflight
	)
)

// init registers everything in Reg so the /metrics endpoint exports
// them all. Anything new added to this file must be added here too.
func init() {
	Reg.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		AuthLoginFailures,
		AuthIPLockouts,
		ScanJobsCreated,
		ScanJobsCompleted,
		FindingsIngested,
		FindingsDeduplicated,
		AuditChainBreaks,
		EvidenceIntegrityFailures,
		AESGCMSeals,
		AuditTSAFailures,
		NotifyQuarantine,
		TenantPoolDowngrade,
		InboundHMACFailures,
		AgentsByStatus,
		IntegrationDeliveryFailures,
		IntegrationDeadLetterDepth,
		EmergencyStopSLAms,
		WorkerTickDuration,
		DBPoolAcquired,
		DBPoolIdle,
		DBPoolWaiting,
		DBPoolMax,
		DBPoolAcquireCount,
		DBPoolAcquireDuration,
		DBPoolCanceledAcquires,
		RateLimitHits,
		IdempotencyHits,
	)
}

// PromHandler mounts the /metrics endpoint with the standard
// promhttp.HandlerFor wired to our registry. Excluded from the
// SecurityHeaders + Auth middleware in api/server.go because Prom
// scrapes it pseudonymously from inside the cluster.
func PromHandler() http.Handler {
	return promhttp.HandlerFor(Reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// HTTPDurationMiddleware records request count + latency. Wraps
// every route in api.Mount.
func HTTPDurationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Wrap the writer so we can capture the status code without
		// forcing the handler to spell it out.
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		dur := time.Since(start).Seconds()
		route := routeLabel(r)
		HTTPRequestsTotal.WithLabelValues(route, r.Method, strconv.Itoa(rw.status)).Inc()
		HTTPRequestDuration.WithLabelValues(route, r.Method).Observe(dur)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// routeLabel collapses high-cardinality paths into a stable bucket so
// Prometheus doesn't get one time-series per UUID. /api/v1/users/<id>
// → /api/v1/users/:id. Anything not under /api/v1 is bucketed as
// "other".
func routeLabel(r *http.Request) string {
	p := r.URL.Path
	if len(p) > 7 && p[:7] != "/api/v1" {
		return "other"
	}
	// Strip query.
	if i := indexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	// Replace UUID-shaped segments.
	return normalisePath(p)
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// normalisePath replaces 36-char hex-with-dashes segments + numeric ids
// + 32-char hex ids with `:id`. Keeps cardinality bounded.
func normalisePath(p string) string {
	var b []byte
	parts := split(p, '/')
	for i, seg := range parts {
		if isUUIDish(seg) || isNumeric(seg) || (len(seg) == 32 && isHex(seg)) {
			parts[i] = ":id"
		}
	}
	for i, seg := range parts {
		if i > 0 {
			b = append(b, '/')
		}
		b = append(b, seg...)
	}
	return string(b)
}

func split(s string, sep byte) []string {
	var out []string
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[last:i])
			last = i + 1
		}
	}
	out = append(out, s[last:])
	return out
}

func isUUIDish(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
