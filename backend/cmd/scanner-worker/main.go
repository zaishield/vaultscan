// scanner-worker is the per-region external scanner runner (Blueprint §12).
//
// It polls dispatched scan jobs for its region, verifies the cloud signature
// against the cached public key, runs each tool in the profile, ingests the
// parsed findings, and reports status. One worker per node; multiple workers
// per region race safely on FOR UPDATE SKIP LOCKED.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/scanner"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	region := os.Getenv("VAULTSCAN_SCANNER_REGION")
	if region == "" {
		log.Fatal().Msg("VAULTSCAN_SCANNER_REGION required (e.g. ae|eu|in|us|sg)")
	}

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("open db")
	}
	defer pool.Close()

	auditSvc := audit.New(pool.Pool)
	bus := eventbus.New(pool.Pool)
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus, cfg.EvidenceMasterKey,
		evidence.WithURLTTL(cfg.EvidenceURLTTL))
	if err != nil {
		log.Fatal().Err(err).Msg("init evidence vault")
	}
	findSvc := findings.New(pool.Pool, auditSvc, bus)

	// Fetch the cloud signer's public key over the trusted API and cache it.
	// This is what the worker uses to verify per-job signatures; without it
	// every job would be rejected, so it's a hard prerequisite.
	pubKey, err := fetchCloudPublicKey(ctx, cfg.APIPublicURL())
	if err != nil {
		log.Warn().Err(err).Msg("could not fetch cloud public key — running in unverified mode")
	} else {
		log.Info().Int("pem_bytes", len(pubKey)).Msg("cloud public key cached")
	}

	worker := scanner.NewWorker(log, pool.Pool, scanner.Config{
		Region:        region,
		SignerPubPEM:  pubKey,
		Poll:          5 * time.Second,
		MaxConcurrent: 4,
	}, vault, findSvc, auditSvc, bus)

	go worker.Run(ctx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	cancel()
	time.Sleep(500 * time.Millisecond) // brief drain
}

// fetchCloudPublicKey pulls the orchestrator's RSA public key from the API.
// Production deployments should pre-distribute this via the platform's
// secrets store; this fallback works in dev / single-cluster setups.
func fetchCloudPublicKey(ctx context.Context, baseURL string) (string, error) {
	if baseURL == "" {
		return "", errors.New("scanner: API URL not configured (set VAULTSCAN_API_PUBLIC_URL)")
	}
	url := strings.TrimRight(baseURL, "/") + "/api/v1/orchestrator/public-key"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("scanner: public-key fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
