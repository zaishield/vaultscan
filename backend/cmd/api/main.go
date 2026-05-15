// api is the public REST gateway for VAULTSCAN. It hosts every Blueprint §21
// portal endpoint; the agent gateway is a separate binary for stricter mTLS.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/analytics"
	"github.com/zaishield/vaultscan/backend/internal/api"
	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/authdocs"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/partners"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
	"github.com/zaishield/vaultscan/backend/internal/tenants"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)

	ctx := context.Background()
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

	signer, err := scanorch.NewSigner(cfg.JobSigningKeyID, cfg.JobSigningKeyPEM)
	if err != nil {
		log.Fatal().Err(err).Msg("init job signer")
	}
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus, cfg.EvidenceMasterKey,
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
	agentSvc := agents.New(pool.Pool, auditSvc, bus)
	findSvc := findings.New(pool.Pool, auditSvc, bus)
	retestSvc := retesting.New(pool.Pool, auditSvc, bus, findSvc)
	reportSvc := reporting.New(pool.Pool, brand, vault, auditSvc, bus)
	intSvc := integrations.New(pool.Pool, bus, auditSvc)
	intSvc.Wire(bus)
	dashSvc := dashboards.New(pool.Pool)
	verifier := auth.NewVerifier(cfg.JWTSharedSecret, pool.Pool)

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

	router := api.Mount(&api.Services{
		Pool: pool.Pool, Cfg: cfg, Log: log, Verifier: verifier,
		Audit: auditSvc, Bus: bus, Branding: brand,
		Tenants: tenSvc, Partners: partSvc, Engagements: engSvc, AuthDocs: docSvc,
		Assets: assetSvc, Scope: scope, ScanOrch: orch, Agents: agentSvc,
		Findings: findSvc, Vault: vault, Retests: retestSvc, Reports: reportSvc,
		Integrations: intSvc, Dashboards: dashSvc,
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
	_ = srv.Shutdown(shctx)
}
