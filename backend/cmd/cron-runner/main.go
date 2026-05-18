// cron-runner is the single background-worker binary that drives every
// periodic task in the platform. One process keeps the deployment
// simple — scale by adding replicas when individual tasks need more
// throughput. Tasks run on independent tickers; a slow task can't
// block another.
//
// Tasks (Blueprint §22.4):
//   * findings.SweepSLABreaches              - hourly
//   * evidence.SweepExpired                   - hourly
//   * auth.BruteforceShield.SweepExpired      - every 5 min
//   * scanorch.NodeOps.FailoverStalled        - every 30 sec
//   * reporting.RunDue (scheduled reports)    - every 5 min
//   * audit.VerifyDeep (chain forensics)      - hourly
//   * agents.RollupTelemetry (per active agent) - hourly
//   * audit.ShipBatch (SIEM forwarder)        - every 30 sec
//   * integrations DLQ depth metric refresh   - every 30 sec
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/compliance"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/leader"
	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
	"github.com/zaishield/vaultscan/backend/internal/observability"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Tracing is opt-in via env; sane no-op when unset.
	shutdown, err := observability.InitTracing(ctx, "vaultscan-cron-runner", "1.0.0")
	if err != nil {
		log.Warn().Err(err).Msg("tracing init failed")
	}
	defer func() {
		if shutdown != nil {
			_ = shutdown(context.Background())
		}
	}()

	pool, err := db.OpenForComponent(ctx, cfg.DatabaseURL, "cron-runner")
	if err != nil {
		log.Fatal().Err(err).Msg("open db")
	}
	defer pool.Close()

	auditSvc := audit.New(pool.Pool)
	bus := eventbus.New(pool.Pool)
	storage, err := evidence.NewStorageFromConfig(evidence.StorageConfig{
		Backend:          cfg.EvidenceBackend,
		FilesystemRoot:   cfg.EvidenceFilesystemRoot,
		S3Endpoint:       cfg.ObjectStoreURL,
		S3Bucket:         cfg.ObjectStoreBucket,
		S3Region:         cfg.ObjectStoreRegion,
		S3AccessKey:      cfg.ObjectStoreKey,
		S3SecretKey:      cfg.ObjectStoreSecret,
		S3ForcePathStyle: cfg.EvidenceS3ForcePathStyle,
		S3SSE:            cfg.EvidenceS3SSE,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("init evidence storage")
	}
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus, cfg.EvidenceMasterKey,
		evidence.WithStorage(storage))
	if err != nil {
		log.Fatal().Err(err).Msg("init vault")
	}
	signer, err := scanorch.NewSigner(cfg.JobSigningKeyID, cfg.JobSigningKeyPEM)
	if err != nil {
		log.Fatal().Err(err).Msg("init signer")
	}
	scope := scopeguard.New(pool.Pool)
	orch := scanorch.New(pool.Pool, scope, auditSvc, bus, signer)
	nodeOps, err := scanorch.NewNodeOps(pool.Pool, cfg.ScannerPullKey)
	if err == nil {
		orch = orch.WithNodeOps(nodeOps)
	}
	brand := branding.New(pool.Pool, auditSvc, cfg.BrandingDefault)
	findSvc := findings.New(pool.Pool, auditSvc, bus)
	reportSvc := reporting.New(pool.Pool, brand, vault, auditSvc, bus)
	agentSvc := agents.New(pool.Pool, auditSvc, bus)
	intSvc := integrations.New(pool.Pool, bus, auditSvc)
	bruteforce := auth.NewBruteforceShield(pool.Pool)

	// /metrics + /healthz on a small admin listener. Prometheus scrapes
	// here too — separate port from the API binary so an api outage
	// doesn't blind alerting on cron health.
	go startAdminListener(log, cfg)

	jobs := []job{
		{name: "fail_over_stalled_nodes", interval: 30 * time.Second, fn: func(ctx context.Context) error {
			if nodeOps == nil {
				return nil
			}
			degraded, err := nodeOps.FailoverStalled(ctx)
			if err == nil && len(degraded) > 0 {
				log.Info().Int("nodes", len(degraded)).Msg("auto-degraded stalled scanner nodes")
			}
			return err
		}},
		{name: "auth_ip_lockouts_sweep", interval: 5 * time.Minute, fn: func(ctx context.Context) error {
			_, _, err := bruteforce.SweepExpired(ctx)
			return err
		}},
		{name: "idempotency_keys_sweep", interval: 15 * time.Minute, fn: func(ctx context.Context) error {
			n, err := middleware.SweepIdempotencyKeys(ctx, pool.Pool)
			if err == nil && n > 0 {
				log.Info().Int("purged", n).Msg("idempotency keys swept")
			}
			return err
		}},
		{name: "findings_sla_breach_sweep", interval: time.Hour, fn: func(ctx context.Context) error {
			n, err := findSvc.SweepSLABreaches(ctx)
			if err == nil && n > 0 {
				log.Info().Int("breaches", n).Msg("flagged findings as SLA-breached")
			}
			return err
		}},
		{name: "evidence_retention_sweep", interval: time.Hour, fn: func(ctx context.Context) error {
			n, err := vault.SweepExpired(ctx)
			if err == nil && n > 0 {
				log.Info().Int("purged", n).Msg("evidence vault retention sweep")
			}
			return err
		}},
		{name: "report_schedules_run_due", interval: 5 * time.Minute, fn: func(ctx context.Context) error {
			_, err := reportSvc.RunDue(ctx)
			return err
		}},
		{name: "audit_verify_deep", interval: time.Hour, fn: func(ctx context.Context) error {
			res, err := auditSvc.VerifyDeep(ctx)
			if err != nil {
				return err
			}
			if res.FirstBadID != 0 {
				observability.AuditChainBreaks.Inc()
				log.Error().Int64("first_bad_id", res.FirstBadID).Str("detail", res.Detail).
					Msg("AUDIT CHAIN BROKEN")
			}
			return nil
		}},
		{name: "agent_telemetry_rollup", interval: time.Hour, fn: func(ctx context.Context) error {
			return rollupForEveryAgent(ctx, pool.Pool, agentSvc)
		}},
		{name: "siem_audit_shipping", interval: 30 * time.Second, fn: func(ctx context.Context) error {
			return shipAuditToSIEM(ctx, pool.Pool, auditSvc)
		}},
		{name: "integrations_dlq_depth", interval: 30 * time.Second, fn: func(ctx context.Context) error {
			return refreshDLQDepth(ctx, pool.Pool)
		}},
		// Auto-replay failed integration deliveries that look retry-
		// safe: failure < N minutes old, attempts < N, integration
		// still enabled. Bounded batch per tick so a backlog can't
		// thunder against the downstream. Operators can disable via
		// VAULTSCAN_INTEGRATION_AUTORETRY_DISABLED=true.
		{name: "integrations_dlq_retry", interval: 5 * time.Minute, fn: func(ctx context.Context) error {
			if os.Getenv("VAULTSCAN_INTEGRATION_AUTORETRY_DISABLED") == "true" {
				return nil
			}
			return autoRetryDeadLetters(ctx, pool.Pool, intSvc, log)
		}},
		// Sample-based vault integrity verification post-restore.
		// Picks N random evidence rows, decrypts each, asserts the
		// HMAC + ciphertext round-trip. Surfaces corruption from
		// a backup with bad keys / a partial restore / disk bit-rot.
		{name: "evidence_integrity_sample", interval: time.Hour, fn: func(ctx context.Context) error {
			n := 50
			if v := os.Getenv("VAULTSCAN_EVIDENCE_INTEGRITY_SAMPLE_SIZE"); v != "" {
				if k, err := strconv.Atoi(v); err == nil && k > 0 && k <= 10000 {
					n = k
				}
			}
			if vault == nil {
				return nil
			}
			ok, checked, err := vault.VerifyRandomSample(ctx, n)
			if err != nil {
				return err
			}
			if ok < checked {
				observability.EvidenceIntegrityFailures.Add(float64(checked - ok))
				log.Error().Int("ok", ok).Int("checked", checked).
					Msg("EVIDENCE INTEGRITY: sample verify found mismatches")
			}
			return nil
		}},
		{name: "agent_status_gauge", interval: 30 * time.Second, fn: func(ctx context.Context) error {
			return refreshAgentStatusGauge(ctx, pool.Pool)
		}},
		{name: "partition_maintenance", interval: 6 * time.Hour, fn: func(ctx context.Context) error {
			return ensureNextMonthPartitions(ctx, pool.Pool)
		}},
		{name: "audit_archive_sweep", interval: 6 * time.Hour, fn: func(ctx context.Context) error {
			// Archival is opt-in via env. Default off — many deployments
			// keep audit_logs in-place and rely on Postgres partitioning.
			if os.Getenv("VAULTSCAN_AUDIT_ARCHIVE_ENABLED") != "true" {
				return nil
			}
			dir := os.Getenv("VAULTSCAN_AUDIT_ARCHIVE_DIR")
			if dir == "" {
				dir = "/var/lib/vaultscan/audit-archive"
			}
			storage := audit.NewFilesystemArchive(dir)
			tsa := audit.NewTSAClient(os.Getenv("VAULTSCAN_AUDIT_TSA_URL"))
			arch := audit.NewArchiver(pool.Pool, storage, tsa)
			arch.PurgeAfterArchive = os.Getenv("VAULTSCAN_AUDIT_ARCHIVE_PURGE") == "true"
			_, err := arch.RunOnce(ctx, nil)
			return err
		}},
		{name: "audit_tsa_daily_anchor", interval: 24 * time.Hour, fn: func(ctx context.Context) error {
			tsaURL := os.Getenv("VAULTSCAN_AUDIT_TSA_URL")
			if tsaURL == "" {
				return nil // anchoring disabled
			}
			arch := audit.NewArchiver(pool.Pool, nil, audit.NewTSAClient(tsaURL))
			return arch.AnchorOnce(ctx)
		}},
		{name: "compliance_evaluate", interval: 6 * time.Hour, fn: func(ctx context.Context) error {
			return compliance.NewEvaluator(pool.Pool).EvaluateAll(ctx)
		}},
		// Per-tenant DEK rotation. Default 90-day max age matches SOC2 /
		// ISO27001 expectations for key-material lifetime; override via
		// VAULTSCAN_DEK_ROTATION_DAYS for stricter environments. Old DEK
		// versions remain decryptable (we never retire them in this
		// path; sweep only writes the new version).
		{name: "dek_rotation_sweep", interval: 24 * time.Hour, fn: func(ctx context.Context) error {
			days := 90
			if v := os.Getenv("VAULTSCAN_DEK_ROTATION_DAYS"); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					days = n
				}
			}
			rotated, err := vault.RotateStaleTenantKeys(ctx, time.Duration(days)*24*time.Hour)
			if err == nil && rotated > 0 {
				log.Info().Int("tenants", rotated).Int("max_age_days", days).
					Msg("DEK rotation sweep")
			}
			return err
		}},
		// Re-wrap existing evidence under the new DEK after a rotation.
		// Runs hourly with a bounded batch so a tenant with millions of
		// objects gets chewed through over hours rather than blocking
		// one tick. Idempotent: it's safe to skip ticks and resume.
		{name: "dek_rewrap_sweep", interval: time.Hour, fn: func(ctx context.Context) error {
			batch := 500
			if v := os.Getenv("VAULTSCAN_DEK_REWRAP_BATCH"); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10000 {
					batch = n
				}
			}
			// Pull tenants with objects below the latest version.
			rows, err := pool.Pool.Query(ctx, `
				SELECT DISTINCT fe.tenant_id
				  FROM finding_evidence fe
				  JOIN (
				      SELECT tenant_id, MAX(key_version) AS latest
				        FROM tenant_data_keys
				       WHERE retired_at IS NULL
				       GROUP BY tenant_id
				  ) tdk ON tdk.tenant_id = fe.tenant_id
				 WHERE fe.encrypted = true
				   AND fe.encryption_key_version IS NOT NULL
				   AND fe.encryption_key_version < tdk.latest
				 LIMIT 50`)
			if err != nil {
				return err
			}
			var tenantIDs []uuid.UUID
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err == nil {
					tenantIDs = append(tenantIDs, id)
				}
			}
			rows.Close()

			totalRewrapped := 0
			for _, tid := range tenantIDs {
				n, _, _ := vault.ReWrapTenantObjects(ctx, tid, batch)
				totalRewrapped += n
			}
			if totalRewrapped > 0 {
				log.Info().Int("objects", totalRewrapped).Int("tenants", len(tenantIDs)).
					Msg("DEK re-wrap sweep")
			}
			return nil
		}},
		// Tenant quarantine purger. Hard-deletes tenants whose
		// quarantine window (7 days by default) has elapsed. The
		// platform-admin's POST .../quarantine starts the clock;
		// the matching DELETE cancels it. Once the window closes,
		// the cascade DELETE walks every FK relationship (engagements,
		// findings, evidence, audit_logs, etc.) so the row truly goes
		// away. Override window via VAULTSCAN_QUARANTINE_DAYS.
		{name: "tenant_purge_swept_quarantines", interval: time.Hour, fn: func(ctx context.Context) error {
			days := 7
			if v := os.Getenv("VAULTSCAN_QUARANTINE_DAYS"); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					days = n
				}
			}
			tag, err := pool.Pool.Exec(ctx, `
				DELETE FROM tenants
				 WHERE quarantine_started_at IS NOT NULL
				   AND quarantine_started_at < now() - $1::interval`,
				fmt.Sprintf("%d days", days))
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				log.Warn().Int64("tenants", tag.RowsAffected()).Int("window_days", days).
					Msg("hard-deleted quarantined tenants past window")
			}
			return nil
		}},
		// Compliance rollup snapshot — weekly persisted view so auditors
		// can ask "what did SOC2 coverage look like on this date".
		{name: "compliance_rollup_snapshot", interval: 7 * 24 * time.Hour, fn: func(ctx context.Context) error {
			rows, err := pool.Pool.Query(ctx, `SELECT id FROM tenants WHERE status='active'`)
			if err != nil {
				return err
			}
			var tenantIDs []uuid.UUID
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err == nil {
					tenantIDs = append(tenantIDs, id)
				}
			}
			rows.Close()
			eval := compliance.NewEvaluator(pool.Pool)
			for _, tid := range tenantIDs {
				if _, err := eval.Snapshot(ctx, tid); err != nil {
					log.Warn().Err(err).Str("tenant", tid.String()).Msg("snapshot failed")
				}
			}
			log.Info().Int("tenants", len(tenantIDs)).Msg("compliance rollup snapshot")
			return nil
		}},
		// Expire impersonation sessions older than the expires_at cap.
		// Belt-and-braces — the JWT itself also expires, but cleaning
		// the DB row lets the active-sessions endpoint stay clean.
		{name: "impersonation_session_expirer", interval: 5 * time.Minute, fn: func(ctx context.Context) error {
			_, err := pool.Pool.Exec(ctx, `
				UPDATE support_impersonation_sessions
				   SET ended_at = expires_at
				 WHERE ended_at IS NULL AND expires_at < now()`)
			return err
		}},
	}

	// Wire the integration service onto the in-process event bus so
	// events emitted by THIS cron-runner's tasks (audit-ship,
	// scheduled-report runs, DEK rotation, partition maintenance,
	// etc.) reach configured outbound integrations. Previously the
	// service was instantiated but never wired, so any event whose
	// only emitter was the cron-runner silently fan-out failed.
	intSvc.Wire(bus)

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go runJob(ctx, log, &wg, j, pool.Pool)
	}
	log.Info().Int("jobs", len(jobs)).Msg("cron-runner started")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutting down — draining in-flight ticks")
	cancel()
	wg.Wait()
}

type job struct {
	name     string
	interval time.Duration
	fn       func(ctx context.Context) error
}

// runJob fires the job once on boot, then every `interval`. Each tick
// is wrapped in a per-tick timeout so a stuck task can't pin the
// goroutine forever, and metrics record duration + outcome.
//
// Leader election: every tick takes a Postgres advisory lock keyed on
// the job name. Only the pod that acquires the lock executes the
// work; other replicas record an outcome of "follower" and move on.
// The lock is held for the duration of one tick and released
// immediately so the role can fail over between ticks if the leader
// dies.
func runJob(ctx context.Context, log zerolog.Logger, wg *sync.WaitGroup, j job, pool *pgxpool.Pool) {
	defer wg.Done()
	tick := func() {
		start := time.Now()
		tctx, cancel := context.WithTimeout(ctx, j.interval*4)
		defer cancel()
		wasLeader, err := leader.Run(tctx, pool, j.name, j.fn)
		outcome := "ok"
		if !wasLeader {
			outcome = "follower"
		} else if err != nil {
			outcome = "error"
			log.Warn().Err(err).Str("job", j.name).Msg("cron tick failed")
		}
		observability.WorkerTickDuration.WithLabelValues(j.name, outcome).
			Observe(time.Since(start).Seconds())
	}
	// Initial fire-and-then-tick so boot-time setup happens fast.
	tick()
	t := time.NewTicker(j.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

func startAdminListener(log zerolog.Logger, cfg *config.Config) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", observability.PromHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	addr := os.Getenv("VAULTSCAN_CRON_ADMIN_ADDR")
	if addr == "" {
		addr = ":9091"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Str("addr", addr).Msg("cron admin listener")
	}
	_ = cfg
}

// rollupForEveryAgent walks every agent that's heart-beated in the
// last day and runs RollupTelemetry over the same window. Cheap and
// idempotent — RollupTelemetry uses ON CONFLICT to upsert buckets.
func rollupForEveryAgent(ctx context.Context, pool *pgxpool.Pool, svc *agents.Service) error {
	rows, err := pool.Query(ctx, `
		SELECT id FROM agents
		 WHERE last_heartbeat > now() - INTERVAL '24 hours'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	since := time.Now().UTC().Add(-25 * time.Hour)
	until := time.Now().UTC()
	for _, id := range ids {
		_, _ = svc.RollupTelemetry(ctx, id, since, until)
	}
	return nil
}

// shipAuditToSIEM advances the cursor for every SIEM integration row.
// Empty siem rows just no-op; nothing else to wire.
func shipAuditToSIEM(ctx context.Context, pool *pgxpool.Pool, svc *audit.Service) error {
	rows, err := pool.Query(ctx, `
		SELECT id FROM integrations
		 WHERE type='siem' AND enabled=true`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		_, _, _ = svc.ShipBatch(ctx, id, 500)
	}
	return nil
}

func refreshDLQDepth(ctx context.Context, pool *pgxpool.Pool) error {
	var n float64
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM integration_dead_letters WHERE resolved_at IS NULL`).
		Scan(&n)
	if err != nil {
		return err
	}
	observability.IntegrationDeadLetterDepth.Set(n)
	return nil
}

// autoRetryDeadLetters picks a bounded batch of retry-eligible
// dead-letter entries and calls intSvc.Replay on each. Eligibility:
//   - resolved_at IS NULL                  (still pending)
//   - attempts < 5                         (under the per-DL replay cap)
//   - enqueued_at < now() - 5 min          (give the breaker time to close)
//   - integration is still enabled         (joined)
// Bounded at 100 per tick so a 10k-deep backlog doesn't synchronously
// rip through the downstream API.
func autoRetryDeadLetters(ctx context.Context, pool *pgxpool.Pool, svc *integrations.Service, log zerolog.Logger) error {
	rows, err := pool.Query(ctx, `
		SELECT dl.id
		  FROM integration_dead_letters dl
		  JOIN integrations i ON i.id = dl.integration_id
		 WHERE dl.resolved_at IS NULL
		   AND dl.attempts < 5
		   AND dl.enqueued_at < now() - interval '5 minutes'
		   AND i.enabled = true
		 ORDER BY dl.enqueued_at
		 LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var success, fail int
	for _, id := range ids {
		// nil actor = system-initiated retry; the integration_replays
		// row records `requested_by IS NULL` so an audit can tell
		// system-retries from operator-retries.
		if err := svc.Replay(ctx, id, nil); err != nil {
			fail++
		} else {
			success++
		}
	}
	log.Info().Int("ok", success).Int("fail", fail).Int("total", len(ids)).
		Msg("dlq auto-retry sweep")
	return nil
}

// ensureNextMonthPartitions calls vaultscan_ensure_month_partition
// for the candidate partitioned tables. The function is a no-op for
// tables that haven't been converted to partitioned yet, so it's safe
// to run unconditionally.
func ensureNextMonthPartitions(ctx context.Context, pool *pgxpool.Pool) error {
	tables := []string{"audit_logs", "findings", "scan_jobs", "bus_events"}
	for _, tbl := range tables {
		// Pre-create this month, next month, and the one after — so a
		// 4-week vacation by the cron-runner doesn't leave the default
		// partition catching writes.
		for offset := 0; offset <= 2; offset++ {
			_, _ = pool.Exec(ctx, `
				SELECT vaultscan_ensure_month_partition($1, now() + ($2 || ' month')::interval)`,
				tbl, fmt.Sprintf("%d", offset))
		}
	}
	return nil
}

func refreshAgentStatusGauge(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT status, count(*) FROM agents GROUP BY status`)
	if err != nil {
		return err
	}
	defer rows.Close()
	// Reset all known labels to 0 so a status that just dropped to zero
	// doesn't stick.
	for _, s := range []string{"online", "offline", "pending", "quarantined", "revoked"} {
		observability.AgentsByStatus.WithLabelValues(s).Set(0)
	}
	for rows.Next() {
		var status string
		var count float64
		if err := rows.Scan(&status, &count); err != nil {
			return err
		}
		observability.AgentsByStatus.WithLabelValues(status).Set(count)
	}
	return nil
}

