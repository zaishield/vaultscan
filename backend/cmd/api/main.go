// api is the public REST gateway for VAULTSCAN. It hosts every Blueprint §21
// portal endpoint; the agent gateway is a separate binary for stricter mTLS.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/analytics"
	"github.com/zaishield/vaultscan/backend/internal/api"
	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/cosign"
	"github.com/zaishield/vaultscan/backend/internal/email"
	"github.com/zaishield/vaultscan/backend/internal/users"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/authdocs"
	"github.com/zaishield/vaultscan/backend/internal/billing"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/debugserver"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/envmode"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/guardrails"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
	"github.com/zaishield/vaultscan/backend/internal/observability"
	"github.com/zaishield/vaultscan/backend/internal/partners"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
	"github.com/zaishield/vaultscan/backend/internal/searchindex"
	"github.com/zaishield/vaultscan/backend/internal/tenants"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)

	ctx := context.Background()

	// Wire the per-scope rate-limit hit counter so /metrics shows
	// identity vs tenant trips separately. middleware.SetRateLimitHitSink
	// avoids an import cycle (middleware can't import observability).
	middleware.SetRateLimitHitSink(func(scope string) {
		observability.RateLimitHits.WithLabelValues(scope).Inc()
	})
	middleware.SetIdempotencyHitSink(func(outcome string) {
		observability.IdempotencyHits.WithLabelValues(outcome).Inc()
	})
	// Let the pgx slow-query tracer correlate to request IDs without
	// the db package importing middleware (would cycle).
	db.SetRequestIDExtractor(middleware.RequestIDFromContext)

	// Tracing. No-op when VAULTSCAN_OTEL_EXPORTER is unset; otherwise
	// ships OTLP/HTTP to the configured endpoint (Tempo/Jaeger/Honeycomb).
	shutdown, err := observability.InitTracing(ctx, "vaultscan-api", "1.0.0")
	if err != nil {
		log.Warn().Err(err).Msg("tracing init failed — continuing without traces")
	}
	defer func() {
		if shutdown != nil {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdown(sctx)
		}
	}()
	pool, err := db.OpenForComponent(ctx, cfg.DatabaseURL, "api")
	if err != nil {
		log.Fatal().Err(err).Msg("open database")
	}
	defer pool.Close()
	// Optional read-replica routing. nil-replica is a safe no-op —
	// services with WithReplica() will transparently fall back to
	// the primary. Used by dashboards.
	replica, err := db.OpenReplica(ctx, cfg.DatabaseReplicaURL)
	if err != nil {
		log.Warn().Err(err).Msg("open replica failed — falling back to primary")
	}
	if replica != nil {
		defer replica.Close()
		log.Info().Msg("read-replica configured; dashboards will route reads to replica")
	}
	// Pool stats → Prometheus every 10s. Lets ops alert on saturation
	// (acquired ≈ max, sustained waiting > 0) before user-visible
	// latency spikes.
	stopPoolStats := observability.StartPoolStatsExporter(ctx, pool.Pool, 10*time.Second)
	defer stopPoolStats()

	if applied, err := pool.Migrate(ctx, "backend/migrations"); err != nil {
		log.Warn().Err(err).Msg("migrations failed (continuing if already applied)")
	} else if len(applied) > 0 {
		log.Info().Int("count", len(applied)).Msg("applied migrations")
	}

	auditSvc := audit.New(pool.Pool)
	bus := eventbus.New(pool.Pool)
	// Cross-process delivery via Postgres NOTIFY/LISTEN. No new
	// infra needed; other processes (analytics-worker, scanner-worker,
	// agent-gateway) StartListener() to receive events emitted here.
	bus.EnableNotify()
	bus.StartListener(ctx)

	// §22: attach the external NATS adapter so cross-process consumers
	// (analytics-worker, scanner-worker telemetry) see the same events
	// as the in-process subscribers. Failure to connect is non-fatal —
	// the API keeps running on the in-process bus alone, and bus_events
	// stays the durability record for replay.
	if cfg.EventBusURL != "" && strings.HasPrefix(cfg.EventBusURL, "nats://") {
		if natsSink, err := eventbus.NewNATSAdapter(cfg.EventBusURL); err != nil {
			log.Warn().Err(err).Str("url", cfg.EventBusURL).
				Msg("nats adapter not wired — events stay in-process only")
		} else {
			bus.AttachExternal(natsSink)
			log.Info().Str("nats", cfg.EventBusURL).Msg("event bus fanning out via NATS")
		}
	}

	signer, err := scanorch.NewSigner(cfg.JobSigningKeyID, cfg.JobSigningKeyPEM)
	if err != nil {
		log.Fatal().Err(err).Msg("init job signer")
	}
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
		log.Fatal().Err(err).Msg("init evidence storage backend")
	}
	log.Info().Str("backend", storage.Name()).Msg("evidence storage")
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus, cfg.EvidenceMasterKey,
		evidence.WithStorage(storage),
		evidence.WithURLTTL(cfg.EvidenceURLTTL))
	if err != nil {
		log.Fatal().Err(err).Msg("init evidence vault")
	}

	brand := branding.New(pool.Pool, auditSvc, cfg.BrandingDefault)
	tenSvc := tenants.New(pool.Pool, auditSvc, bus)
	partSvc := partners.New(pool.Pool, auditSvc, bus)
	engSvc := engagements.New(pool.Pool, auditSvc, bus)
	docSvc := authdocs.New(pool.Pool, vault, auditSvc, bus)
	// Billing first so the orchestrator + asset service can pull
	// in the quota gate during their construction.
	billingSvc := billing.New(pool.Pool, bus)
	assetSvc := assets.New(pool.Pool, auditSvc).WithBilling(billingSvc)
	scope := scopeguard.New(pool.Pool)
	orch := scanorch.New(pool.Pool, scope, auditSvc, bus, signer).
		WithBilling(billingSvc)
	if reg, err := scanorch.NewImageDigestRegistry(
		getenvOr("VAULTSCAN_SCANNER_DIGESTS_PATH", "tools/scanner-images/digests.json"),
	); err == nil {
		orch = orch.WithDigests(reg)
		if v := reg.Version(); v != "" {
			log.Info().Str("digests_version", v).
				Int("tools_pinned", len(reg.All())).Msg("scanner image digests loaded")
		}
	} else {
		log.Warn().Err(err).Msg("scanner image digests not loaded; falling back to :latest")
	}
	agentSvc := agents.New(pool.Pool, auditSvc, bus).WithBilling(billingSvc)
	findSvc := findings.New(pool.Pool, auditSvc, bus)
	retestSvc := retesting.New(pool.Pool, auditSvc, bus, findSvc, orch)
	reportSvc := reporting.New(pool.Pool, brand, vault, auditSvc, bus)
	intSvc := integrations.New(pool.Pool, bus, auditSvc)
	// Bounded worker pool for outbound deliveries. Replaces the prior
	// `go s.deliver(...)` fan-out which (a) was unbounded and (b) used
	// context.Background() so SIGTERM killed in-flight calls mid-DLQ-write.
	deliverPool := integrations.NewWorkerPool(ctx, intSvc, 16, 256)
	intSvc.AttachWorkerPool(deliverPool)
	intSvc.Wire(bus)
	dashSvc := dashboards.New(pool.Pool).WithReplica(replica)
	userSvc := users.New(pool.Pool, auditSvc)
	emailSvc := email.New(pool.Pool, nil) // production wires SMTP/SES; dev uses MemoryTransport
	cosignSvc := cosign.New(pool.Pool)
	brandAssets := branding.NewAssetService(pool.Pool, vault, auditSvc)
	// CDN signing for brand assets, if configured. Modes:
	//   disabled    — pass-through (legacy default)
	//   prefix      — naive prefix swap onto VAULTSCAN_CDN_PUBLIC_BASE
	//   cloudfront  — RSA-SHA1 canned-policy signed URLs
	if cfg.CDNMode != "" && cfg.CDNMode != "disabled" {
		cdnCfg := branding.CDNConfig{
			Mode:       branding.CDNMode(cfg.CDNMode),
			PublicBase: cfg.CDNPublicBase,
			SignedTTL:  cfg.CDNSignedTTL,
			KeyPairID:  cfg.CDNKeyPairID,
		}
		if cfg.CDNMode == "cloudfront" && cfg.CDNPrivateKeyPath != "" {
			if keyPEM, kerr := os.ReadFile(cfg.CDNPrivateKeyPath); kerr == nil {
				if k, perr := branding.LoadCloudFrontKey(keyPEM); perr == nil {
					cdnCfg.PrivateKey = k
				} else {
					log.Warn().Err(perr).Msg("brand assets: cloudfront key parse failed; falling back to direct fetch")
				}
			} else {
				log.Warn().Err(kerr).Str("path", cfg.CDNPrivateKeyPath).
					Msg("brand assets: cloudfront key file unreadable; falling back to direct fetch")
			}
		}
		brandAssets.SetCDNConfig(cdnCfg)
		log.Info().Str("mode", cfg.CDNMode).Str("base", cfg.CDNPublicBase).
			Msg("brand assets: CDN signing enabled")
	}
	verifier := auth.NewVerifier(cfg.JWTSharedSecret, pool.Pool)

	// Deepened-service surface (VS-05/VS-12 + HS-01/HS-05). NodeOps gets
	// the per-tenant pull-credential KEK from config; if it's empty,
	// pull-credential storage is refused (admin UI surfaces the error).
	nodeOps, err := scanorch.NewNodeOps(pool.Pool, cfg.ScannerPullKey)
	if err != nil {
		log.Warn().Err(err).Msg("scanorch.NodeOps not wired — pull credentials disabled")
	} else {
		orch = orch.WithNodeOps(nodeOps)
	}
	// Cross-region failover ladder.
	// Format: VAULTSCAN_REGION_FAILOVER="us-east-1=us-west-2,us-east-2;eu-west-1=eu-central-1"
	if spec := os.Getenv("VAULTSCAN_REGION_FAILOVER"); spec != "" {
		orch = orch.WithFailoverRegions(scanorch.NewFailoverRegionsFromEnv(spec))
		log.Info().Str("spec", spec).Msg("scanner cross-region failover ladder configured")
	}
	liveStream := dashboards.NewLiveStream(bus)
	guardrailSvc := guardrails.New(pool.Pool, auditSvc)
	bruteforce := auth.NewBruteforceShield(pool.Pool)

	// Real TOTP/MFA + RSA JWT key management. Both share the platform
	// KEK so a single rotation covers both surfaces. Bootstrap ensures
	// there's always at least one active signing key on boot.
	mfaSvc, err := auth.NewMFAService(pool.Pool, cfg.EvidenceMasterKey)
	if err != nil {
		log.Warn().Err(err).Msg("MFA service not configured — /api/v1/auth/mfa/* will 500")
	}
	keyMgr, err := auth.NewKeyManager(pool.Pool, cfg.EvidenceMasterKey)
	if err != nil {
		log.Warn().Err(err).Msg("JWT key manager not configured — RS256 issuance disabled")
	} else {
		if _, err := keyMgr.Bootstrap(ctx); err != nil {
			log.Warn().Err(err).Msg("JWT key bootstrap failed")
		}
		verifier = verifier.WithKeyManager(keyMgr)
	}
	// Production lockdown: forbid HS256 tokens once we have RS256 wired.
	// HS256 stays available in dev/staging so test tooling keeps working
	// without standing up a full key manager.
	if envmode.IsProduction(cfg.Env) {
		verifier = verifier.WithRefuseHMAC(true)
	}

	// Optional in-process analytics indexer. The standalone analytics-worker
	// is preferred for production; set VAULTSCAN_ANALYTICS_INPROC=false to
	// disable this when running the worker separately.
	if os.Getenv("VAULTSCAN_ANALYTICS_INPROC") != "false" {
		if asClient, err := analytics.NewClient(cfg.OpenSearchURL, "", ""); err == nil {
			if err := asClient.Ping(ctx); err != nil {
				log.Warn().Err(err).Msg("opensearch unreachable; analytics indexer disabled")
			} else {
				if err := analytics.EnsureTemplates(ctx, asClient); err != nil {
					log.Warn().Err(err).Msg("ensure analytics templates")
				}
				idx := analytics.NewIndexer(asClient, pool.Pool, log)
				idx.Wire(bus)
				go idx.Run(ctx)
				log.Info().Msg("in-process analytics indexer active")
			}
		}
	}

	// Findings + audit search indexer. Separate from analytics — this
	// is per-document search, not aggregated dashboards.
	if cfg.OpenSearchURL != "" {
		searchClient, err := searchindex.New(searchindex.Config{
			URL:      cfg.OpenSearchURL,
			Username: os.Getenv("VAULTSCAN_OPENSEARCH_USER"),
			Password: os.Getenv("VAULTSCAN_OPENSEARCH_PASSWORD"),
		})
		if err != nil {
			log.Warn().Err(err).Msg("searchindex client init failed")
		} else {
			if _, err := searchClient.Health(ctx); err != nil {
				log.Warn().Err(err).Msg("opensearch unreachable; search index disabled")
			} else {
				_ = searchClient.EnsureIndex(ctx, searchindex.FindingsIndexName,
					searchindex.FindingsIndexMapping())
				_ = searchClient.EnsureIndex(ctx, searchindex.AuditIndexName,
					searchindex.AuditIndexMapping())
				findingsIdx := searchindex.NewFindingsIndexer(searchClient)
				bus.Subscribe(eventbus.FindingNormalized, findingsIdx.HandleEvent)
				log.Info().Msg("findings search index active")
			}
		}
	}

	// Resolve the default partner ID once at boot from the
	// configured slug. Replaces the previous hardcoded sentinel
	// UUID (00000000-0000-0000-0000-0000000000b1) that several
	// handlers used as a fallback partner — renaming / re-slugging
	// the seeded partner now keeps working as long as the operator
	// updates VAULTSCAN_DEFAULT_PARTNER_SLUG to match.
	var defaultPartnerID uuid.UUID
	if dp, derr := partSvc.DefaultBySlug(ctx, cfg.DefaultPartnerSlug); derr == nil {
		defaultPartnerID = dp.ID
	} else {
		log.Warn().Err(derr).Str("slug", cfg.DefaultPartnerSlug).
			Msg("api: default partner slug not found; handlers that need a fallback partner will return 400")
	}

	router := api.Mount(&api.Services{
		Pool: pool.Pool, Cfg: cfg, Log: log, Verifier: verifier,
		Audit: auditSvc, Bus: bus, Branding: brand,
		Tenants: tenSvc, Partners: partSvc, Engagements: engSvc, AuthDocs: docSvc,
		Assets: assetSvc, Scope: scope, ScanOrch: orch, Signer: signer, Agents: agentSvc,
		Findings: findSvc, Vault: vault, Retests: retestSvc, Reports: reportSvc,
		Integrations: intSvc, Dashboards: dashSvc, Users: userSvc, Email: emailSvc,
		Cosign: cosignSvc, BrandAssets: brandAssets,
		Billing:          billingSvc,
		DefaultPartnerID: defaultPartnerID,
		Nodes: nodeOps, LiveStream: liveStream,
		Guardrails: guardrailSvc, Bruteforce: bruteforce,
		MFA: mfaSvc, Keys: keyMgr,
	})

	// Wrap the router so every request gets an OTel span with the route
	// label attached. When VAULTSCAN_OTEL_EXPORTER is unset the global
	// provider is a no-op and this adds ~microseconds per request; when
	// it's configured the spans flow to Tempo/Jaeger/Honeycomb.
	tracedRouter := observability.TracingHandler(router, "vaultscan-api")

	srv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           tracedRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 * 1024, // 32 KiB header cap; default 1 MiB is too generous
	}

	go func() {
		log.Info().Str("addr", cfg.APIAddr).Msg("vaultscan api listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("api server")
		}
	}()

	// Debug / pprof server on a dedicated port — production network
	// policy locks this down independently of the public API. Empty
	// VAULTSCAN_DEBUG_ADDR disables the server entirely (default).
	var debugSrv *http.Server
	if cfg.DebugAddr != "" {
		debugSrv = debugserver.New(cfg.DebugAddr, cfg.DebugToken)
		go func() {
			log.Info().Str("addr", cfg.DebugAddr).
				Bool("token_required", cfg.DebugToken != "").
				Msg("vaultscan debug server listening")
			if err := debugSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Warn().Err(err).Msg("debug server")
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutdown requested")
	shctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Drain HTTP first so no new outbound deliveries are queued; then
	// drain the worker pool (10s grace) so in-flight DLQ writes land.
	_ = srv.Shutdown(shctx)
	if debugSrv != nil {
		_ = debugSrv.Shutdown(shctx)
	}
	deliverPool.Shutdown(10 * time.Second)
	if n := deliverPool.OverflowCount(); n > 0 {
		log.Warn().Int("dropped", n).Msg("integration deliveries dropped due to queue saturation")
	}
	// Drain in-flight external bus sinks (NATS Forward goroutines).
	bus.DrainExternal(5 * time.Second)
}

func getenvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
