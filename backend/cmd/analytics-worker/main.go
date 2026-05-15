// analytics-worker is the OpenSearch indexer that mirrors authoritative
// Postgres records into the analytics index family (Blueprint §26.4).
// It runs separately from the API so OpenSearch backpressure or downtime
// can never affect the user-facing path.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/zaishield/vaultscan/backend/internal/analytics"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/logging"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("open db")
	}
	defer pool.Close()

	client, err := analytics.NewClient(cfg.OpenSearchURL, "", "")
	if err != nil {
		log.Fatal().Err(err).Msg("init opensearch client")
	}
	if err := client.Ping(ctx); err != nil {
		log.Warn().Err(err).Msg("opensearch ping failed; will retry as events arrive")
	}
	if err := analytics.EnsureTemplates(ctx, client); err != nil {
		log.Warn().Err(err).Msg("ensure index templates")
	}

	bus := eventbus.New(pool.Pool)
	indexer := analytics.NewIndexer(client, pool.Pool, log)
	indexer.Wire(bus)

	go indexer.Run(ctx)

	log.Info().Str("opensearch", cfg.OpenSearchURL).Msg("analytics worker running")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutdown")
	cancel()
}
