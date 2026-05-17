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
	"github.com/zaishield/vaultscan/backend/internal/cosign"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/envmode"
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
	// Cross-process delivery: events the worker publishes
	// (ExternalScanStarted, FindingNormalized, ...) reach the API +
	// analytics-worker via Postgres NOTIFY.
	bus.EnableNotify()
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
		evidence.WithStorage(storage),
		evidence.WithURLTTL(cfg.EvidenceURLTTL))
	if err != nil {
		log.Fatal().Err(err).Msg("init evidence vault")
	}
	findSvc := findings.New(pool.Pool, auditSvc, bus)

	// Fetch the cloud signer's public key. Without it the per-job
	// signature gate in scanner.Worker.execute degrades to "if pubKey
	// != ''" — i.e. fail-open — and an attacker who can write to
	// scan_jobs (compromised API or DB) gets arbitrary code execution
	// on the scanner-worker via unsigned tool commands.
	//
	// Production refuses to boot without the key. Dev keeps the
	// warn-and-continue path so first-time setup doesn't break before
	// the orchestrator has provisioned its key.
	pubKey, err := fetchCloudPublicKey(ctx, cfg.APIPublicURL())
	if err != nil {
		if envmode.IsProduction(cfg.Env) {
			log.Fatal().Err(err).
				Msg("scanner-worker refuses to boot in production without the cloud public key — unsigned jobs would otherwise execute")
		}
		log.Warn().Err(err).Msg("could not fetch cloud public key — running in unverified mode (dev only)")
	} else {
		log.Info().Int("pem_bytes", len(pubKey)).Msg("cloud public key cached")
	}

	cosignSvc := cosign.New(pool.Pool)
	// Production deployments require both signed images AND signed job
	// payloads. Default ON in production, off in dev so first-boot demos
	// don't break. VAULTSCAN_REQUIRE_SIGNED_IMAGES=false overrides ONLY
	// in dev — production ignores the override and stays strict.
	requireSigs := envmode.IsProduction(cfg.Env)
	if !envmode.IsProduction(cfg.Env) {
		requireSigs = os.Getenv("VAULTSCAN_REQUIRE_SIGNED_IMAGES") == "true"
	}

	worker := scanner.NewWorker(log, pool.Pool, scanner.Config{
		Region:            region,
		SignerPubPEM:      pubKey,
		Poll:              5 * time.Second,
		MaxConcurrent:     4,
		RequireSignatures: requireSigs,
	}, vault, findSvc, auditSvc, bus, cosignSvc)

	go worker.Run(ctx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("scanner-worker: shutdown requested, draining in-flight jobs")
	cancel()
	// 30s grace lets a typical mid-flight scan land its final
	// scan_jobs UPDATE + findings INSERTs. Process supervisor's
	// terminationGracePeriodSeconds must be >= this.
	worker.Shutdown(30 * time.Second)
	log.Info().Msg("scanner-worker: shutdown complete")
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
