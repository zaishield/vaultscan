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
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/envmode"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/guardrails"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/logging"
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
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("open database")
	}
	defer pool.Close()

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
	assetSvc := assets.New(pool.Pool, auditSvc)
	scope := scopeguard.New(pool.Pool)
	orch := scanorch.New(pool.Pool, scope, auditSvc, bus, signer)
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
	agentSvc := agents.New(pool.Pool, auditSvc, bus)
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
	dashSvc := dashboards.New(pool.Pool)
	userSvc := users.New(pool.Pool, auditSvc)
	emailSvc := email.New(pool.Pool, nil) // production wires SMTP/SES; dev uses MemoryTransport
	cosignSvc := cosign.New(pool.Pool)
	brandAssets := branding.NewAssetService(pool.Pool, vault, auditSvc)
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

	router := api.Mount(&api.Services{
		Pool: pool.Pool, Cfg: cfg, Log: log, Verifier: verifier,
		Audit: auditSvc, Bus: bus, Branding: brand,
		Tenants: tenSvc, Partners: partSvc, Engagements: engSvc, AuthDocs: docSvc,
		Assets: assetSvc, Scope: scope, ScanOrch: orch, Signer: signer, Agents: agentSvc,
		Findings: findSvc, Vault: vault, Retests: retestSvc, Reports: reportSvc,
		Integrations: intSvc, Dashboards: dashSvc, Users: userSvc, Email: emailSvc,
		Cosign: cosignSvc, BrandAssets: brandAssets,
		Nodes: nodeOps, LiveStream: liveStream,
		Guardrails: guardrailSvc, Bruteforce: bruteforce,
		MFA: mfaSvc, Keys: keyMgr,
	})

	srv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		log.Info().Str("addr", cfg.APIAddr).Msg("vaultscan api listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("api server")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutdown requested")
	shctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Drain HTTP first so no new outbound deliveries are queued; then
	// drain the worker pool (10s grace) so in-flight DLQ writes land.
	_ = srv.Shutdown(shctx)
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
