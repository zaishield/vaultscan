package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
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
	runner       ExecRunner
	vault        *evidence.Vault
	findings     *findings.Service
	audit        *audit.Service
	bus          *eventbus.Bus
	signerPubPEM      string // cloud signer's public key, for verifying job signatures
	requireSignatures bool   // production: true → refuse to run a job when signerPubPEM is empty
	poll              time.Duration
	maxConcurrent     int

	// inflight tracks goroutines spawned by Run so Shutdown can block
	// until every in-flight execute returns. Without this, a
	// SIGTERM at the wrong moment leaves a half-written scan_job
	// row in the DB while the binary exits.
	inflight sync.WaitGroup
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
		runner:        mustRunnerFromEnv(log),
		vault:         vault,
		findings:      findSvc,
		audit:         auditSvc,
		bus:           bus,
		signerPubPEM:      cfg.SignerPubPEM,
		requireSignatures: cfg.RequireSignatures,
		poll:              cfg.Poll,
		maxConcurrent:     cfg.MaxConcurrent,
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
		w.inflight.Add(1)
		go func() {
			defer w.inflight.Done()
			defer func() { <-sem }()
			// Recover from panics inside execute so a single bad
			// parser / scanner output doesn't crash the entire
			// worker process and require pod restart. Stack
			// trace logged for forensics; job left in 'running'
			// (operator can use emergency-stop to clear it).
			defer func() {
				if r := recover(); r != nil {
					w.log.Error().Interface("panic", r).
						Str("job_id", job.ID.String()).
						Bytes("stack", debug.Stack()).
						Msg("scanner: panic recovered in execute")
				}
			}()
			w.execute(ctx, job)
		}()
	}
}

// Shutdown blocks until either every in-flight execute() returns or
// the deadline elapses. Designed to be called from main after the
// process ctx is cancelled — gives running jobs a bounded chance
// to land their final scan_jobs UPDATE + findings INSERT instead of
// leaving the system mid-write.
func (w *Worker) Shutdown(deadline time.Duration) {
	done := make(chan struct{})
	go func() {
		w.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(deadline):
		w.log.Warn().Dur("deadline", deadline).
			Msg("scanner worker shutdown deadline elapsed with jobs still in flight")
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
	//
	// When RequireSignatures is true the worker refuses to run unsigned
	// jobs even if the public key is missing — boot-time check has
	// already fatal'd in production, so this is belt-and-braces.
	switch {
	case w.signerPubPEM != "":
		manifest := scanorch.CanonicalManifest(
			j.ID, j.TenantID, j.EngagementID,
			j.ProfileCode, "external", nil,
			j.Tools, j.Targets,
		)
		if err := scanorch.VerifyExternal(w.signerPubPEM, manifest, j.JobSignature); err != nil {
			w.log.Error().Err(err).Str("scan_job_id", j.ID.String()).
				Msg("scanner: refusing to run job — signature verification failed")
			w.failJob(ctx, j, "signature verification failed: "+err.Error())
			return
		}
	case w.requireSignatures:
		// Production posture: refuse to run if the worker booted
		// without a cached public key. The boot-time guard in
		// cmd/scanner-worker should have fatal'd already; this
		// branch is a defence-in-depth net so a runtime config
		// reload that clears the key can't allow unsigned jobs.
		w.log.Error().Str("scan_job_id", j.ID.String()).
			Msg("scanner: refusing to run job — RequireSignatures=true and no cached public key")
		w.failJob(ctx, j, "signature verification skipped: no public key cached, but RequireSignatures=true")
		return
	default:
		// Dev / single-tenant deploy: signatures disabled by config.
		// Emit one warn-level breadcrumb per job so this is visible
		// in production-by-accident misconfigurations.
		w.log.Warn().Str("scan_job_id", j.ID.String()).
			Msg("scanner: running job WITHOUT signature verification (RequireSignatures=false)")
	}

	_ = w.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ExternalScanStarted, TenantID: &j.TenantID, PartnerID: &j.PartnerID,
		Payload: map[string]any{"scan_job_id": j.ID, "region": w.region},
	})

	anyToolRan := false
	for _, tool := range j.Tools {
		w.markTaskState(ctx, j.ID, tool, "running", nil, nil)
		img, err := w.registry.Lookup(ctx, tool, "external")
		if err != nil {
			w.log.Warn().Err(err).Str("tool", tool).Msg("tool not in image registry — skipping")
			w.markTaskState(ctx, j.ID, tool, "skipped", nil, map[string]any{"reason": "no image in registry"})
			continue
		}
		// Image digest + cosign verification (Blueprint §12.3). VerifyImage
		// chains the cheap digest check with the expensive crypto check;
		// the dev runner doesn't expose a runtime digest so VerifyDigest
		// soft-passes there, but the cosign path runs unconditionally.
		if _, err := w.registry.VerifyImage(ctx, img, "", "external", nil); err != nil {
			w.log.Warn().Err(err).Str("tool", tool).Str("image", img.Reference).
				Msg("image verification rejected — skipping tool")
			w.markTaskState(ctx, j.ID, tool, "skipped", nil, map[string]any{"reason": "image verification rejected"})
			continue
		}

		res, err := w.runner.Run(ctx, tool, j.Targets, 30*time.Minute)
		if err != nil {
			// Distinguish "binary missing in production" from a generic
			// run failure. ErrSyntheticForbidden is structural — fail the
			// whole job, don't continue silently.
			if errors.Is(err, ErrSyntheticForbidden) {
				w.log.Error().Err(err).Str("tool", tool).
					Msg("scanner binary missing and synthetic output forbidden — failing job")
				w.markTaskState(ctx, j.ID, tool, "failed", nil, map[string]any{"reason": "binary missing; synthetic forbidden"})
				w.failJob(ctx, j, "scanner binary missing: "+tool)
				return
			}
			w.log.Warn().Err(err).Str("tool", tool).Msg("tool run failed; continuing")
			w.markTaskState(ctx, j.ID, tool, "failed", nil, map[string]any{"error": err.Error()})
			continue
		}
		// Defense in depth: even if AllowSynthetic was true at runner
		// init, refuse to ingest synthetic output unless explicitly
		// permitted by env. Belt-and-braces against a misconfigured
		// scanner image that ships without the tools.
		if res.Synthetic && !w.runner.AllowsSynthetic() {
			w.log.Error().Str("tool", tool).
				Msg("runner returned synthetic output but synthetics disabled; refusing")
			w.failJob(ctx, j, "synthetic scanner output rejected")
			return
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
		var ingestedCount int
		if parser, ok := parsers.Registry[tool]; ok {
			ingested, err := parser(parsers.Context{
				PlatformID: j.PlatformID, PartnerID: j.PartnerID,
				TenantID: j.TenantID, EngagementID: j.EngagementID,
				ScanJobID: &j.ID,
			}, res.Output)
			if err != nil {
				w.log.Warn().Err(err).Str("tool", tool).Msg("parse output")
				w.markTaskState(ctx, j.ID, tool, "failed",
					intPtr(res.ExitCode),
					map[string]any{"parse_error": err.Error(), "synthetic": res.Synthetic})
				continue
			}
			for _, in := range ingested {
				if _, _, err := w.findings.Upsert(ctx, in); err != nil {
					w.log.Warn().Err(err).Str("tool", tool).Msg("ingest finding")
				} else {
					ingestedCount++
				}
			}
		}
		w.markTaskState(ctx, j.ID, tool, "succeeded",
			intPtr(res.ExitCode),
			map[string]any{
				"synthetic":    res.Synthetic,
				"output_bytes": len(res.Output),
				"ingested":     ingestedCount,
			})
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

// markTaskState updates the scan_tasks row for (jobID, tool) with the
// given status + optional exit code + JSON output summary. Used to give
// ops a per-tool execution timeline (which binary ran, which were
// skipped because the registry didn't know them, which crashed).
//
// The orchestrator pre-inserts the row at "queued" when it dispatches
// the job, so this is always an UPDATE. Errors are logged + swallowed
// — scan progress shouldn't fail because of an audit row write.
func (w *Worker) markTaskState(ctx context.Context, jobID uuid.UUID, tool, status string, exitCode *int, summary map[string]any) {
	var summaryJSON []byte
	if summary != nil {
		summaryJSON, _ = json.Marshal(summary)
	}
	var startCol, endCol string
	switch status {
	case "running":
		startCol = ", started_at = now()"
	case "succeeded", "failed", "skipped":
		endCol = ", completed_at = now()"
	}
	q := `UPDATE scan_tasks
	         SET status = $3, exit_code = $4, output_summary = $5::jsonb` +
		startCol + endCol + `
	       WHERE scan_job_id = $1 AND tool = $2`
	if _, err := w.pool.Exec(ctx, q, jobID, tool, status, exitCode, summaryJSON); err != nil {
		w.log.Warn().Err(err).Str("tool", tool).Msg("update scan_tasks state")
	}
}

func intPtr(n int) *int { return &n }

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
