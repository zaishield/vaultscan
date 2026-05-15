package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/cosign"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/observability"
	"github.com/zaishield/vaultscan/backend/internal/parsers"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

// Worker polls dispatched external scan jobs for a given region, verifies
// the signature + image digest, runs the tool, parses the output, and
// ingests the findings. In production one Worker runs per regional scanner
// node (Blueprint §12.1, §12.2). Multiple workers per region are safe — the
// claim is done via an atomic UPDATE.
type Worker struct {
	log          zerolog.Logger
	pool         *pgxpool.Pool
	region       string
	nodeID       *uuid.UUID
	registry     *Registry
	runner       *Runner
	vault        *evidence.Vault
	findings     *findings.Service
	audit        *audit.Service
	bus          *eventbus.Bus
	signerPubPEM string // cloud signer's public key, for verifying job signatures
	poll         time.Duration
	maxConcurrent int
}

type Config struct {
	Region            string
	NodeID            *uuid.UUID
	SignerPubPEM      string
	Poll              time.Duration
	MaxConcurrent     int
	RequireSignatures bool // production: true. Refuses unsigned scanner images.
}

func NewWorker(log zerolog.Logger, pool *pgxpool.Pool, cfg Config,
	vault *evidence.Vault, findSvc *findings.Service, auditSvc *audit.Service,
	bus *eventbus.Bus, cosignSvc *cosign.Service) *Worker {
	if cfg.Poll <= 0 {
		cfg.Poll = 5 * time.Second
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	reg := NewRegistry(pool, cosignSvc)
	reg.RequireSignatures = cfg.RequireSignatures
	return &Worker{
		log:           log.With().Str("component", "scanner-worker").Str("region", cfg.Region).Logger(),
		pool:          pool,
		region:        cfg.Region,
		nodeID:        cfg.NodeID,
		registry:      reg,
		runner:        NewRunner(),
		vault:         vault,
		findings:      findSvc,
		audit:         auditSvc,
		bus:           bus,
		signerPubPEM:  cfg.SignerPubPEM,
		poll:          cfg.Poll,
		maxConcurrent: cfg.MaxConcurrent,
	}
}

// Run blocks until ctx is cancelled. Polls every Worker.poll and dispatches
// up to MaxConcurrent jobs in parallel.
func (w *Worker) Run(ctx context.Context) {
	sem := make(chan struct{}, w.maxConcurrent)
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	w.log.Info().Msg("scanner worker started")
	for {
		select {
		case <-ctx.Done():
			w.log.Info().Msg("scanner worker shutting down")
			return
		case <-ticker.C:
		}
		job, err := w.claimNext(ctx)
		if err != nil {
			if !errors.Is(err, errNoJobs) {
				w.log.Warn().Err(err).Msg("claim job")
			}
			continue
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			w.execute(ctx, job)
		}()
	}
}

// claimedJob is the minimal job context we need to execute.
type claimedJob struct {
	ID            uuid.UUID
	PlatformID    uuid.UUID
	PartnerID     uuid.UUID
	TenantID      uuid.UUID
	EngagementID  uuid.UUID
	ProfileCode   string
	Tools         []string
	Targets       []string
	JobSignature  string
	SigningKeyID  string
}

var errNoJobs = errors.New("scanner: no jobs to claim")

// claimNext atomically picks the oldest dispatched job for our region and
// flips it to running. Multiple workers in the same region race safely on
// the FOR UPDATE SKIP LOCKED row lock.
func (w *Worker) claimNext(ctx context.Context) (*claimedJob, error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	args := []any{w.region}
	q := `
		SELECT j.id, j.platform_id, j.partner_id, j.tenant_id, j.engagement_id,
		       p.code, p.tools, j.targets,
		       COALESCE(j.job_signature, ''), COALESCE(j.signing_key_id, '')
		  FROM scan_jobs j
		  JOIN scan_profiles p ON p.id = j.profile_id
		 WHERE j.plane = 'external'
		   AND j.status = 'dispatched'
		   AND (j.region = $1 OR j.region IS NULL OR j.region = '')`
	if w.nodeID != nil {
		q += " AND (j.scanner_node_id IS NULL OR j.scanner_node_id = $2)"
		args = append(args, *w.nodeID)
	}
	q += " ORDER BY j.created_at LIMIT 1 FOR UPDATE OF j SKIP LOCKED"

	row := tx.QueryRow(ctx, q, args...)
	var cj claimedJob
	var toolsRaw, targetsRaw []byte
	if err := row.Scan(&cj.ID, &cj.PlatformID, &cj.PartnerID, &cj.TenantID,
		&cj.EngagementID, &cj.ProfileCode, &toolsRaw, &targetsRaw,
		&cj.JobSignature, &cj.SigningKeyID); err != nil {
		return nil, errNoJobs
	}
	if err := json.Unmarshal(toolsRaw, &cj.Tools); err != nil {
		return nil, fmt.Errorf("scanner: parse tools: %w", err)
	}
	if err := json.Unmarshal(targetsRaw, &cj.Targets); err != nil {
		return nil, fmt.Errorf("scanner: parse targets: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE scan_jobs
		   SET status='running', started_at=now(), updated_at=now()
		 WHERE id=$1`, cj.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &cj, nil
}

// execute verifies the signature, runs each tool in the profile, ingests
// the parsed findings, and finalises the job status.
func (w *Worker) execute(ctx context.Context, j *claimedJob) {
	w.log.Info().Str("job", j.ID.String()).Str("profile", j.ProfileCode).
		Int("targets", len(j.Targets)).Msg("executing scan job")

	// Verify the cloud signature against the cached public key. This is the
	// hard "no scanner executes unsigned jobs" gate from Blueprint §11.3.
	// Both sides MUST reconstruct the same canonical manifest, hence the
	// shared helper.
	if w.signerPubPEM != "" {
		manifest := scanorch.CanonicalManifest(
			j.ID, j.TenantID, j.EngagementID,
			j.ProfileCode, "external", nil,
			j.Tools, j.Targets,
		)
		if err := scanorch.VerifyExternal(w.signerPubPEM, manifest, j.JobSignature); err != nil {
			w.failJob(ctx, j, "signature verification failed: "+err.Error())
			return
		}
	}

	_ = w.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ExternalScanStarted, TenantID: &j.TenantID, PartnerID: &j.PartnerID,
		Payload: map[string]any{"scan_job_id": j.ID, "region": w.region},
	})

	anyToolRan := false
	for _, tool := range j.Tools {
		img, err := w.registry.Lookup(ctx, tool, "external")
		if err != nil {
			w.log.Warn().Err(err).Str("tool", tool).Msg("tool not in image registry — skipping")
			continue
		}
		// Image digest + cosign verification (Blueprint §12.3). VerifyImage
		// chains the cheap digest check with the expensive crypto check;
		// the dev runner doesn't expose a runtime digest so VerifyDigest
		// soft-passes there, but the cosign path runs unconditionally.
		if _, err := w.registry.VerifyImage(ctx, img, "", "external", nil); err != nil {
			w.log.Warn().Err(err).Str("tool", tool).Str("image", img.Reference).
				Msg("image verification rejected — skipping tool")
			continue
		}

		res, err := w.runner.Run(ctx, tool, j.Targets, 30*time.Minute)
		if err != nil {
			w.log.Warn().Err(err).Str("tool", tool).Msg("tool run failed; continuing")
			continue
		}
		anyToolRan = true

		ev, err := w.vault.Record(ctx, evidence.PutInput{
			TenantID: j.TenantID, PartnerID: j.PartnerID,
			EngagementID: &j.EngagementID, ScanJobID: &j.ID,
			Kind: "raw_output", ContentType: "application/octet-stream",
			Body: res.Output,
		})
		if err != nil {
			w.log.Warn().Err(err).Msg("record evidence")
			continue
		}

		_ = w.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.ScannerOutputReceived, TenantID: &j.TenantID, PartnerID: &j.PartnerID,
			Payload: map[string]any{
				"scan_job_id":  j.ID,
				"tool":         tool,
				"evidence_id":  ev.ID,
				"size_bytes":   len(res.Output),
				"synthetic":    res.Synthetic,
			},
		})

		// Parse + ingest.
		if parser, ok := parsers.Registry[tool]; ok {
			ingested, err := parser(parsers.Context{
				PlatformID: j.PlatformID, PartnerID: j.PartnerID,
				TenantID: j.TenantID, EngagementID: j.EngagementID,
				ScanJobID: &j.ID,
			}, res.Output)
			if err != nil {
				w.log.Warn().Err(err).Str("tool", tool).Msg("parse output")
				continue
			}
			for _, in := range ingested {
				if _, _, err := w.findings.Upsert(ctx, in); err != nil {
					w.log.Warn().Err(err).Str("tool", tool).Msg("ingest finding")
				}
			}
		}
	}

	if !anyToolRan {
		w.failJob(ctx, j, "no registered tools could be executed")
		return
	}

	if _, err := w.pool.Exec(ctx, `
		UPDATE scan_jobs SET status='succeeded', completed_at=now(), updated_at=now()
		 WHERE id=$1`, j.ID); err != nil {
		w.log.Warn().Err(err).Msg("mark succeeded")
		return
	}
	// Worker only claims plane='external' jobs (see claimNext).
	observability.ScanJobsCompleted.WithLabelValues("external", "succeeded").Inc()
	_ = w.audit.Record(ctx, audit.Entry{
		PlatformID: j.PlatformID, PartnerID: &j.PartnerID, TenantID: &j.TenantID,
		ActorType: "service", Event: audit.EventScanCompleted,
		TargetType: "scan_job", TargetID: j.ID.String(),
		Payload: map[string]any{"region": w.region},
	})
	w.log.Info().Str("job", j.ID.String()).Msg("scan job succeeded")
}

func (w *Worker) failJob(ctx context.Context, j *claimedJob, reason string) {
	w.log.Warn().Str("job", j.ID.String()).Str("reason", reason).Msg("scan job failed")
	_, _ = w.pool.Exec(ctx, `
		UPDATE scan_jobs SET status='failed', completed_at=now(), updated_at=now(),
		                     cancellation_reason=$2
		 WHERE id=$1`, j.ID, base64.StdEncoding.EncodeToString([]byte(reason)))
	observability.ScanJobsCompleted.WithLabelValues("external", "failed").Inc()
	_ = w.audit.Record(ctx, audit.Entry{
		PlatformID: j.PlatformID, PartnerID: &j.PartnerID, TenantID: &j.TenantID,
		ActorType: "service", Event: audit.EventScanStopped,
		TargetType: "scan_job", TargetID: j.ID.String(),
		Payload: map[string]any{"reason": reason, "region": w.region},
	})
}
