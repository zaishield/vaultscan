// analytics-worker is the OpenSearch indexer that mirrors authoritative
// Postgres records into the analytics index family (Blueprint §26.4).
// It runs separately from the API so OpenSearch backpressure or downtime
// can never affect the user-facing path.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

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

	pool, err := db.OpenForComponent(ctx, cfg.DatabaseURL, "analytics-worker")
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
	// Receive events from other processes via Postgres NOTIFY.
	bus.EnableNotify()
	bus.StartListener(ctx)
	indexer := analytics.NewIndexer(client, pool.Pool, log)
	indexer.Wire(bus)

	// Cross-process events arrive via NATS — the API binary attaches a
	// NATSAdapter to its bus so every Publish lands on
	// vaultscan.<event-type>. Subscribe with the wildcard so we pick
	// up every type the indexer knows how to handle.
	if cfg.EventBusURL != "" && strings.HasPrefix(cfg.EventBusURL, "nats://") {
		nc, err := nats.Connect(cfg.EventBusURL,
			nats.Name("vaultscan-analytics-worker"),
			nats.MaxReconnects(-1))
		if err != nil {
			log.Warn().Err(err).Msg("nats connect failed — running in-process-only mode")
		} else {
			_, _ = nc.Subscribe("vaultscan.>", func(m *nats.Msg) {
				var ev eventbus.Event
				if err := json.Unmarshal(m.Data, &ev); err != nil {
					return
				}
				indexer.Handle(context.Background(), ev)
			})
			defer nc.Drain()
			log.Info().Str("nats", cfg.EventBusURL).Msg("subscribed to NATS event bus")
		}
	}

	go indexer.Run(ctx)

	// Lightweight health endpoint for kube probes.
	//   /healthz: always 200 once the indexer goroutine is started
	//             (liveness — restart only if the process is stuck).
	//   /readyz : 200 only when both DB + OpenSearch are reachable
	//             (readiness — gate from Service load balancing).
	// Probes hit :9090; that port is exposed in the helm chart.
	var ready atomic.Bool
	go func() {
		// Periodically refresh readiness so a transient outage
		// flips the gate within ~10s.
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		check := func() {
			pctx, pc := context.WithTimeout(context.Background(), 3*time.Second)
			defer pc()
			if err := pool.Pool.Ping(pctx); err != nil {
				ready.Store(false); return
			}
			if err := client.Ping(pctx); err != nil {
				ready.Store(false); return
			}
			ready.Store(true)
		}
		check()
		for {
			select {
			case <-ctx.Done(): return
			case <-tick.C: check()
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready.Load() {
			fmt.Fprintln(w, "ok"); return
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	})
	probeSrv := &http.Server{
		Addr:              ":9090",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := probeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warn().Err(err).Msg("probe server exited")
		}
	}()

	log.Info().Str("opensearch", cfg.OpenSearchURL).Msg("analytics worker running")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutdown")
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = probeSrv.Shutdown(sctx)
	cancel()
}
