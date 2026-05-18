// Package scanorch is the scan orchestrator (Blueprint §5, §11.2). It signs
// jobs, picks an external scanner region or internal agent, and emits the
// lifecycle events the rest of the platform consumes.
package scanorch

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"hash/fnv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
	"github.com/zaishield/vaultscan/backend/internal/observability"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
)

type Orchestrator struct {
	pool      *pgxpool.Pool
	guard     *scopeguard.Service
	audit     *audit.Service
	bus       *eventbus.Bus
	signer    *Signer
	// Nodes is optional — when set, the picker honors per-region quotas and
	// auto-failover. nil falls back to the legacy "any online node" behaviour
	// for callers that haven't wired the VS-05 op surface yet.
	Nodes *NodeOps
	// Digests is an optional pinned-image registry. When non-nil the
	// task materialiser writes <registry>/<tool>@sha256:<digest>
	// references into scan_tasks.image_ref so the worker pulls an
	// immutable + cosign-signed image. nil → mutable :latest fallback.
	Digests *ImageDigestRegistry
	// FallbackRegistry is the registry hostname used when Digests is
	// nil OR a tool isn't pinned. Defaults to the production registry.
	FallbackRegistry string
	// Failover is the cross-region failover ladder consulted when
	// the primary region has no eligible node. Optional — nil = no
	// failover, just error out per the legacy behaviour.
	Failover *FailoverRegions

	// billing is the per-partner scan-quota gate. nil = no
	// enforcement (the legacy / dev path); production wires this
	// via WithBilling.
	billing QuotaChecker

	// residency enforces the tenant's data_region pin against the
	// pod's VAULTSCAN_REGION. nil = no enforcement; production wires
	// this via WithResidency.
	residency ResidencyChecker
	// podRegion is the deployment-zone code the pod runs in. Used
	// together with residency. Empty = no check possible.
	podRegion string
}

// ResidencyChecker is the slice of tenants.Service needed for the
// scanorch.Submit residency gate. Defined as an interface so scanorch
// doesn't pull in the full tenants package at link time.
type ResidencyChecker interface {
	CheckResidency(ctx context.Context, tenantID uuid.UUID, podRegion string) error
}

// WithResidency attaches the residency checker + the pod's region.
// Empty region disables the check.
func (o *Orchestrator) WithResidency(r ResidencyChecker, podRegion string) *Orchestrator {
	o.residency = r
	o.podRegion = podRegion
	return o
}

// WithDigests attaches an ImageDigestRegistry. main.go calls this
// after loading tools/scanner-images/digests.json.
func (o *Orchestrator) WithDigests(d *ImageDigestRegistry) *Orchestrator {
	o.Digests = d
	return o
}

// imageRefFor returns the scan_tasks.image_ref value: pinned digest
// reference when available.
//
// Behavior depends on the registry's strict flag:
//   strict=true  → returns ("", ErrNoDigest) for unpinned tools.
//                  Caller (Submit) propagates this as a submission
//                  failure; the API maps it to 503 unpinned_image.
//   strict=false → falls back to <registry>/<tool>:latest with a
//                  one-time warning via unpinnedSink. Used in dev /
//                  pre-release-tag environments.
func (o *Orchestrator) imageRefFor(tool string) (string, error) {
	fallback := o.FallbackRegistry
	if fallback == "" {
		fallback = "registry.zaishield.com/vaultscan/scanners"
	}
	if o.Digests != nil {
		if o.Digests.Strict() {
			return o.Digests.ImageRefForStrict(tool, fallback)
		}
		return o.Digests.ImageRefFor(tool, fallback), nil
	}
	return fallback + "/" + tool + ":latest", nil
}

func New(pool *pgxpool.Pool, g *scopeguard.Service, a *audit.Service, b *eventbus.Bus, s *Signer) *Orchestrator {
	return &Orchestrator{pool: pool, guard: g, audit: a, bus: b, signer: s}
}

// WithNodeOps attaches the VS-05 health/quota service. Returns o for chain.
func (o *Orchestrator) WithNodeOps(n *NodeOps) *Orchestrator {
	o.Nodes = n
	return o
}

// QuotaChecker is the slice of billing.Service the orchestrator
// actually needs. Defined as an interface so scanorch doesn't pull
// in the full billing package at link time (and so tests can stub
// it with a fixture that returns "always allow" or a specific
// ErrQuotaExceeded).
type QuotaChecker interface {
	CheckScan(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID) error
}

// WithBilling attaches the billing-quota service. Submit() calls
// CheckScan before INSERT; ErrQuotaExceeded propagates out so the
// API handler can return a 429 with structured detail.
func (o *Orchestrator) WithBilling(b QuotaChecker) *Orchestrator {
	o.billing = b
	return o
}

type SubmitInput struct {
	PlatformID    uuid.UUID
	PartnerID     uuid.UUID
	TenantID      uuid.UUID
	EngagementID  uuid.UUID
	ProfileCode   string
	Plane         string                  // external | internal
	Region        string
	AgentID       *uuid.UUID
	Targets       []string
	ScheduleAt    *time.Time
	RequestedBy   *uuid.UUID
	Intensity     string

	// IdempotencyKey is an optional caller-supplied identifier. When
	// present, two Submit() calls with the same key return the same
	// job (the second call is a no-op insert). Without this, a
	// caller that retries Submit() after a transient DB failure can
	// land two near-identical jobs in the queue. Internal callers
	// (retesting.LaunchScan) should derive a stable key from their
	// own identifiers (e.g. retest_id) so re-execution is safe.
	IdempotencyKey string
}

// Submit performs Scope Guard evaluation, persists the job, signs it, and
// (if approved) dispatches to scanner farm or agent queue.
func (o *Orchestrator) Submit(ctx context.Context, in SubmitInput) (out *models.ScanJob, dec *scopeguard.Decision, err error) {
	ctx, end := observability.Span(ctx, "scanorch.Submit",
		"tenant_id", in.TenantID.String(),
		"engagement_id", in.EngagementID.String(),
		"profile_code", in.ProfileCode,
		"plane", in.Plane,
		"target_count", strconv.Itoa(len(in.Targets)),
	)
	defer func() { end(err) }()
	if len(in.Targets) == 0 {
		return nil, nil, errors.New("scanorch: at least one target required")
	}
	// Data-residency gate. Runs FIRST because a residency violation
	// means we shouldn't have routed this request to this pod at all
	// — burning quota + scope-guard cycles on a request we're about
	// to refuse is wasted work. Returns ErrResidencyViolation; the
	// API maps that to 451 Unavailable For Legal Reasons.
	if o.residency != nil && o.podRegion != "" {
		if err := o.residency.CheckResidency(ctx, in.TenantID, o.podRegion); err != nil {
			return nil, nil, err
		}
	}
	// Partner billing-quota gate. Runs BEFORE scope-guard because a
	// quota-blocked partner shouldn't even see the engagement /
	// scope guard cost; the API returns a 429 and the caller
	// upgrades their plan. nil billing service = no enforcement
	// (dev / single-tenant deploys without billing wired).
	if o.billing != nil {
		if err := o.billing.CheckScan(ctx, in.PartnerID, in.RequestedBy); err != nil {
			return nil, nil, err
		}
	}
	// Idempotency: if the caller supplied a key, check for an
	// existing job with the same key+tenant first. Two Submit() calls
	// with the same key always return the same job (no duplicate
	// insert), closing the window where a transient DB failure
	// causes the caller to retry and land two near-identical rows.
	if in.IdempotencyKey != "" {
		var existingID uuid.UUID
		err := o.pool.QueryRow(ctx, `
			SELECT id FROM scan_jobs
			 WHERE tenant_id=$1 AND idempotency_key=$2
			 ORDER BY created_at DESC LIMIT 1`,
			in.TenantID, in.IdempotencyKey).Scan(&existingID)
		if err == nil {
			existing, lerr := o.Get(ctx, existingID)
			if lerr == nil {
				return existing, nil, nil
			}
		}
	}
	// Resolve the profile.
	prof, err := o.profileByCode(ctx, in.ProfileCode)
	if err != nil {
		return nil, nil, err
	}
	if prof.Plane != in.Plane {
		return nil, nil, fmt.Errorf("scanorch: profile %s is %s, request is %s",
			in.ProfileCode, prof.Plane, in.Plane)
	}

	// Per-target scope guard evaluation. The strictest decision wins.
	var lastDecision *scopeguard.Decision
	for _, t := range in.Targets {
		recent := o.recentJobsForTenantLastHour(ctx, in.TenantID)
		dec, err := o.guard.Evaluate(ctx, scopeguard.Inputs{
			TenantID: in.TenantID, PartnerID: in.PartnerID,
			EngagementID: in.EngagementID, ScanProfile: in.ProfileCode,
			TargetType: detectTargetType(t), TargetValue: t, Plane: in.Plane,
			AgentID: in.AgentID, ScannerRegion: in.Region,
			RequestedBy: in.RequestedBy, RecentJobsLastHour: recent,
			Intensity: in.Intensity,
		})
		if err != nil {
			return nil, nil, err
		}
		lastDecision = dec
		if dec.Code != scopeguard.DecisionApproved && dec.Code != scopeguard.DecisionRequiresManualApproval {
			return nil, dec, nil
		}
	}

	// Build the scan job record.
	job := &models.ScanJob{
		ID: uuid.New(), PlatformID: in.PlatformID, PartnerID: in.PartnerID,
		TenantID: in.TenantID, EngagementID: in.EngagementID,
		ProfileID: prof.ID, ProfileCode: prof.Code,
		Plane: in.Plane, Region: in.Region, AgentID: in.AgentID,
		Status: "pending", Targets: in.Targets,
		TargetSummary:    summarizeTargets(in.Targets),
		ScheduleAt:       in.ScheduleAt,
		RequiresApproval: prof.RequiresApproval || lastDecision.Code == scopeguard.DecisionRequiresManualApproval,
		RequestedBy:      in.RequestedBy,
		SigningKeyID:     o.signer.KeyID(),
	}

	// Pick a scanner node for external jobs.
	if in.Plane == "external" {
		nid, err := o.pickScannerNode(ctx, in.Region)
		if err != nil {
			return nil, nil, err
		}
		job.ScannerNodeID = &nid
	}

	// Sign the canonical job manifest. The shape MUST stay reproducible by
	// the scanner worker / agent purely from the scan_jobs row — anything
	// else (timestamps, env-dependent fields) would make verification
	// impossible after restart.
	manifest := CanonicalManifest(job.ID, job.TenantID, job.EngagementID,
		prof.Code, job.Plane, in.AgentID, prof.Tools, in.Targets)
	sig, err := o.signer.Sign(manifest)
	if err != nil {
		return nil, nil, err
	}
	job.JobSignature = sig

	targetsJSON, _ := json.Marshal(in.Targets)
	if err := o.pool.QueryRow(ctx, `
		INSERT INTO scan_jobs(id, platform_id, partner_id, tenant_id, engagement_id, profile_id,
		    plane, region, agent_id, scanner_node_id, status, target_summary, targets,
		    schedule_at, requires_approval, job_signature, signing_key_id, requested_by,
		    idempotency_key)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18,
		       NULLIF($19,'')
		-- TOCTOU guard: revalidate the two critical Scope Guard
		-- preconditions atomically with the INSERT. If the
		-- engagement was paused/expired OR the auth doc was deleted
		-- between Scope Guard approval and this insert, the row
		-- count is 0 and we surface a sentinel error so callers can
		-- treat it as a late-arriving denial.
		WHERE EXISTS (
		  SELECT 1 FROM engagements e
		   WHERE e.id = $5
		     AND e.status = 'active'
		     AND now() BETWEEN e.starts_at AND e.ends_at
		)
		AND EXISTS (
		  SELECT 1 FROM authorization_documents WHERE engagement_id = $5
		)
		RETURNING created_at`,
		job.ID, job.PlatformID, job.PartnerID, job.TenantID, job.EngagementID, job.ProfileID,
		job.Plane, nullIfEmpty(job.Region), job.AgentID, job.ScannerNodeID, job.Status,
		job.TargetSummary, targetsJSON, job.ScheduleAt, job.RequiresApproval,
		job.JobSignature, job.SigningKeyID, job.RequestedBy, in.IdempotencyKey,
	).Scan(&job.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Late-arriving denial: engagement state changed under us.
			return nil, &scopeguard.Decision{
				Code:   scopeguard.DecisionBlockedMissingAuth,
				Reason: "engagement state changed between approval and insert (paused/expired or auth doc removed)",
			}, nil
		}
		// Unique-violation on (tenant_id, idempotency_key) means a
		// concurrent Submit() with the same key won the race. Re-
		// read and return the existing job rather than surfacing
		// the raw 23505 to the caller — that's the whole point of
		// the idempotency key.
		if in.IdempotencyKey != "" && isUniqueViolation(err) {
			var existingID uuid.UUID
			if qerr := o.pool.QueryRow(ctx, `
				SELECT id FROM scan_jobs
				 WHERE tenant_id=$1 AND idempotency_key=$2
				 ORDER BY created_at DESC LIMIT 1`,
				in.TenantID, in.IdempotencyKey).Scan(&existingID); qerr == nil {
				if existing, gerr := o.Get(ctx, existingID); gerr == nil {
					return existing, nil, nil
				}
			}
		}
		return nil, nil, fmt.Errorf("scanorch: insert scan_job: %w", err)
	}

	// Materialize per-tool tasks.
	for _, tool := range prof.Tools {
		taskID := uuid.New()
		imageRef, refErr := o.imageRefFor(tool)
		if refErr != nil {
			// Strict-mode + unpinned tool. Refuse the whole submit
			// rather than dispatch a fraction of the profile's
			// tools — partial scans are misleading.
			return nil, nil, refErr
		}
		if _, ierr := o.pool.Exec(ctx, `
			INSERT INTO scan_tasks(id, scan_job_id, tool, image_ref, status,
			    cpu_limit, memory_limit, runtime_limit_s)
			VALUES ($1,$2,$3,$4,'queued','2','4Gi',1800)`,
			taskID, job.ID, tool, imageRef); ierr != nil {
			return nil, nil, ierr
		}
	}

	// If internal: enqueue on agent.
	if job.Plane == "internal" && job.AgentID != nil {
		if _, err := o.pool.Exec(ctx, `
			INSERT INTO agent_job_queue(agent_id, scan_job_id, state)
			VALUES ($1,$2,'queued')`, *job.AgentID, job.ID); err != nil {
			return nil, nil, err
		}
	}

	_ = o.audit.Record(ctx, audit.Entry{
		PlatformID: job.PlatformID, PartnerID: &job.PartnerID, TenantID: &job.TenantID,
		ActorID: in.RequestedBy, Event: audit.EventScanCreated,
		TargetType: "scan_job", TargetID: job.ID.String(),
		Payload: map[string]any{"profile": prof.Code, "plane": job.Plane,
			"region": job.Region, "targets": len(in.Targets),
			"requires_approval": job.RequiresApproval},
	})
	_ = o.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ScanJobCreated, TenantID: &job.TenantID, PartnerID: &job.PartnerID,
		ActorID: in.RequestedBy,
		Payload: map[string]any{"scan_job_id": job.ID, "profile": prof.Code, "plane": job.Plane},
	})
	observability.ScanJobsCreated.WithLabelValues(job.Plane).Inc()

	if !job.RequiresApproval {
		// Approve flips DB state to 'dispatched' but our in-memory `job`
		// still says 'pending'. Re-fetch so callers see what the worker
		// will pick up.
		approved, err := o.Approve(ctx, job.ID, in.RequestedBy)
		if err != nil {
			return nil, nil, err
		}
		job = approved
	}
	return job, lastDecision, nil
}

// Approve transitions a job from pending → dispatched.
func (o *Orchestrator) Approve(ctx context.Context, jobID uuid.UUID, actor *uuid.UUID) (*models.ScanJob, error) {
	tag, err := o.pool.Exec(ctx, `
		UPDATE scan_jobs
		   SET status='dispatched', approved_by=COALESCE(approved_by, $2), approved_at=now(),
		       updated_at=now()
		 WHERE id=$1 AND status IN ('pending')`, jobID, actor)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, errors.New("scanorch: job not pending")
	}
	job, err := o.Get(ctx, jobID)
	if err != nil {
		return nil, err
	}
	_ = o.audit.Record(ctx, audit.Entry{
		PlatformID: job.PlatformID, PartnerID: &job.PartnerID, TenantID: &job.TenantID,
		ActorID: actor, Event: audit.EventScanApproved,
		TargetType: "scan_job", TargetID: jobID.String(),
	})
	_ = o.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ScanJobApproved, TenantID: &job.TenantID, PartnerID: &job.PartnerID,
		ActorID: actor, Payload: map[string]any{"scan_job_id": jobID},
	})
	if job.Plane == "external" {
		_ = o.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.ExternalScanStarted, TenantID: &job.TenantID, PartnerID: &job.PartnerID,
			ActorID: actor, Payload: map[string]any{"scan_job_id": jobID, "region": job.Region},
		})
	} else {
		_ = o.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.InternalScanDispatched, TenantID: &job.TenantID, PartnerID: &job.PartnerID,
			ActorID: actor, Payload: map[string]any{"scan_job_id": jobID, "agent_id": job.AgentID},
		})
	}
	return job, nil
}

// EmergencyStop transitions all running jobs (or one job) to stopped state and
// emits the EmergencyStopTriggered event. Records the wall-time latency
// from start-of-call to last-row-processed into the EmergencyStopSLAms
// histogram so we can alert on §11.6's 30-second SLO.
func (o *Orchestrator) EmergencyStop(ctx context.Context, actor *uuid.UUID, scope EmergencyScope) (int, error) {
	start := time.Now()
	defer func() {
		observability.EmergencyStopSLAms.Observe(float64(time.Since(start).Milliseconds()))
	}()
	var args []any
	q := `UPDATE scan_jobs SET status='stopped', cancellation_reason=$1, updated_at=now()
	       WHERE status IN ('pending','approved','dispatched','running')`
	reason := scope.Reason
	if reason == "" {
		reason = "emergency_stop"
	}
	args = append(args, reason)
	if scope.JobID != nil {
		q += fmt.Sprintf(" AND id=$%d", len(args)+1)
		args = append(args, *scope.JobID)
	}
	if scope.TenantID != nil {
		q += fmt.Sprintf(" AND tenant_id=$%d", len(args)+1)
		args = append(args, *scope.TenantID)
	}
	if scope.AgentID != nil {
		q += fmt.Sprintf(" AND agent_id=$%d", len(args)+1)
		args = append(args, *scope.AgentID)
	}
	q += " RETURNING id, platform_id, partner_id, tenant_id"
	rows, err := o.pool.Query(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, pid, partnerID, tenantID uuid.UUID
		if err := rows.Scan(&id, &pid, &partnerID, &tenantID); err != nil {
			return count, err
		}
		count++
		_ = o.audit.Record(ctx, audit.Entry{
			PlatformID: pid, PartnerID: &partnerID, TenantID: &tenantID,
			ActorID: actor, Event: audit.EventEmergencyStop,
			TargetType: "scan_job", TargetID: id.String(),
		})
		_ = o.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.EmergencyStopTriggered, TenantID: &tenantID, PartnerID: &partnerID,
			ActorID: actor, Payload: map[string]any{"scan_job_id": id},
		})
		// Stopped jobs count as completed (with status=stopped).
		// We don't know the plane at this point without an extra column
		// scan; use "unknown" rather than 0 — operators can filter by
		// status="stopped" and tolerate the small label cardinality cost.
		observability.ScanJobsCompleted.WithLabelValues("unknown", "stopped").Inc()
	}
	return count, rows.Err()
}

type EmergencyScope struct {
	JobID    *uuid.UUID
	TenantID *uuid.UUID
	AgentID  *uuid.UUID
	// Reason is operator-supplied free-text explaining why the stop
	// fired. Stored on scan_jobs.cancellation_reason for the
	// post-incident audit. Defaults to "emergency_stop" when empty.
	Reason string
}

func (o *Orchestrator) Get(ctx context.Context, id uuid.UUID) (*models.ScanJob, error) {
	job := &models.ScanJob{}
	var targetsJSON []byte
	err := o.pool.QueryRow(ctx, `
		SELECT j.id, j.platform_id, j.partner_id, j.tenant_id, j.engagement_id, j.profile_id,
		       p.code, j.plane, COALESCE(j.region,''), j.agent_id, j.scanner_node_id, j.status,
		       j.target_summary, j.targets, j.schedule_at, j.started_at, j.completed_at,
		       j.requires_approval, j.approved_by, j.approved_at,
		       COALESCE(j.job_signature,''), COALESCE(j.signing_key_id,''),
		       j.requested_by, COALESCE(j.cancellation_reason,''), j.created_at
		  FROM scan_jobs j JOIN scan_profiles p ON p.id = j.profile_id
		 WHERE j.id=$1`, id).
		Scan(&job.ID, &job.PlatformID, &job.PartnerID, &job.TenantID, &job.EngagementID,
			&job.ProfileID, &job.ProfileCode, &job.Plane, &job.Region, &job.AgentID,
			&job.ScannerNodeID, &job.Status, &job.TargetSummary, &targetsJSON,
			&job.ScheduleAt, &job.StartedAt, &job.CompletedAt, &job.RequiresApproval,
			&job.ApprovedBy, &job.ApprovedAt, &job.JobSignature, &job.SigningKeyID,
			&job.RequestedBy, &job.CancellationReason, &job.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsJSON, &job.Targets)
	return job, nil
}

func (o *Orchestrator) ListByTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]models.ScanJob, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := o.pool.Query(ctx, `
		SELECT j.id, j.platform_id, j.partner_id, j.tenant_id, j.engagement_id, j.profile_id,
		       p.code, j.plane, COALESCE(j.region,''), j.agent_id, j.scanner_node_id, j.status,
		       j.target_summary, j.targets, j.schedule_at, j.started_at, j.completed_at,
		       j.requires_approval, j.approved_by, j.approved_at,
		       COALESCE(j.job_signature,''), COALESCE(j.signing_key_id,''),
		       j.requested_by, COALESCE(j.cancellation_reason,''), j.created_at
		  FROM scan_jobs j JOIN scan_profiles p ON p.id = j.profile_id
		 WHERE j.tenant_id=$1
		 ORDER BY j.created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ScanJob{}
	for rows.Next() {
		var j models.ScanJob
		var targetsJSON []byte
		if err := rows.Scan(&j.ID, &j.PlatformID, &j.PartnerID, &j.TenantID, &j.EngagementID,
			&j.ProfileID, &j.ProfileCode, &j.Plane, &j.Region, &j.AgentID, &j.ScannerNodeID,
			&j.Status, &j.TargetSummary, &targetsJSON, &j.ScheduleAt, &j.StartedAt, &j.CompletedAt,
			&j.RequiresApproval, &j.ApprovedBy, &j.ApprovedAt, &j.JobSignature, &j.SigningKeyID,
			&j.RequestedBy, &j.CancellationReason, &j.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsJSON, &j.Targets)
		out = append(out, j)
	}
	return out, rows.Err()
}

// Profiles returns the static profile catalogue.
func (o *Orchestrator) Profiles(ctx context.Context) ([]models.ScanProfile, error) {
	rows, err := o.pool.Query(ctx, `
		SELECT id, code, name, plane, intensity, COALESCE(description,''),
		       tools, parameters, requires_approval
		  FROM scan_profiles ORDER BY plane, code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ScanProfile
	for rows.Next() {
		var p models.ScanProfile
		var tools, params []byte
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Plane, &p.Intensity, &p.Description,
			&tools, &params, &p.RequiresApproval); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tools, &p.Tools)
		_ = json.Unmarshal(params, &p.Parameters)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (o *Orchestrator) profileByCode(ctx context.Context, code string) (*models.ScanProfile, error) {
	p := &models.ScanProfile{}
	var tools, params []byte
	err := o.pool.QueryRow(ctx, `
		SELECT id, code, name, plane, intensity, COALESCE(description,''),
		       tools, parameters, requires_approval
		  FROM scan_profiles WHERE code=$1`, code).
		Scan(&p.ID, &p.Code, &p.Name, &p.Plane, &p.Intensity, &p.Description,
			&tools, &params, &p.RequiresApproval)
	if err != nil {
		return nil, fmt.Errorf("scanorch: profile %q not found", code)
	}
	_ = json.Unmarshal(tools, &p.Tools)
	_ = json.Unmarshal(params, &p.Parameters)
	return p, nil
}

func (o *Orchestrator) recentJobsForTenantLastHour(ctx context.Context, tenant uuid.UUID) int {
	var n int
	_ = o.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM scan_jobs
		 WHERE tenant_id=$1 AND created_at > now() - INTERVAL '1 hour'`, tenant).Scan(&n)
	return n
}

// FailoverRegions defines the cross-region failover ladder consulted
// by pickScannerNode when a job's primary region has no eligible
// node (offline / quota-saturated / no nodes registered). Operators
// configure this via VAULTSCAN_REGION_FAILOVER per-region:
//
//   us-east-1=us-west-2,us-east-2
//   eu-west-1=eu-central-1,eu-west-2
//
// Lookups are case-insensitive. Empty / unset = no failover (current
// region only).
type FailoverRegions struct {
	// ladder[primary] = ordered list of fallback regions to try.
	ladder map[string][]string
}

// NewFailoverRegionsFromEnv parses VAULTSCAN_REGION_FAILOVER. The
// env-var format is `primary=fb1,fb2;primary2=fb3` — semicolon-
// separated entries, each "<primary>=<csv-fallbacks>".
func NewFailoverRegionsFromEnv(spec string) *FailoverRegions {
	f := &FailoverRegions{ladder: map[string][]string{}}
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		var list []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				list = append(list, s)
			}
		}
		if len(list) > 0 {
			f.ladder[key] = list
		}
	}
	return f
}

// Fallbacks returns the ordered fallback list for primary, or nil if
// none configured.
func (f *FailoverRegions) Fallbacks(primary string) []string {
	if f == nil {
		return nil
	}
	return f.ladder[strings.ToLower(primary)]
}

// WithFailoverRegions attaches the cross-region failover ladder.
// Returns o for fluent chaining alongside WithNodeOps / WithDigests.
func (o *Orchestrator) WithFailoverRegions(f *FailoverRegions) *Orchestrator {
	o.Failover = f
	return o
}

func (o *Orchestrator) pickScannerNode(ctx context.Context, region string) (uuid.UUID, error) {
	// Try the primary region first; on miss / saturation walk the
	// configured failover ladder. Each attempt is logged via a
	// scanner_failover_attempts row so operators can alert on
	// chronic primary unavailability.
	tried := []string{region}
	if id, err := o.pickInRegion(ctx, region); err == nil {
		return id, nil
	} else if !errors.Is(err, ErrRegionAtQuota) && !isNoNodeErr(err) {
		// Hard error (DB down) — don't fall back, surface it.
		return uuid.Nil, err
	}
	for _, fb := range o.Failover.Fallbacks(region) {
		tried = append(tried, fb)
		id, err := o.pickInRegion(ctx, fb)
		if err == nil {
			o.recordFailover(ctx, region, fb)
			return id, nil
		}
	}
	return uuid.Nil, fmt.Errorf("%w; tried regions=%v", ErrNoScannerNode, tried)
}

// ErrNoScannerNode is the sentinel returned by pickScannerNode when
// no node is available in the requested region or any failover
// region. Callers use errors.Is(err, ErrNoScannerNode) to decide
// whether to walk the failover ladder vs surface a hard infra
// error — replaces the prior strings.Contains check that broke
// silently when the message text was reworded.
var ErrNoScannerNode = errors.New("scanorch: no scanner node available")

// pickInRegion is the original single-region picker, extracted so
// pickScannerNode can call it once per ladder entry.
func (o *Orchestrator) pickInRegion(ctx context.Context, region string) (uuid.UUID, error) {
	if o.Nodes != nil {
		atQuota, q, err := o.Nodes.IsRegionAtQuota(ctx, region, false)
		if err == nil && atQuota {
			return uuid.Nil, fmt.Errorf("%w: region=%s used %d/%d",
				ErrRegionAtQuota, region, q.Inflight, q.MaxConcurrentJobs)
		}
		if id, err := o.Nodes.EligibleNode(ctx, region); err == nil {
			return id, nil
		}
		// fall through to legacy path so the dev seed (which never
		// heartbeats) still resolves.
	}
	var id uuid.UUID
	q := `SELECT id FROM scanner_node_registry
	       WHERE status='online'`
	args := []any{}
	if region != "" {
		q += " AND region=$1"
		args = append(args, region)
	}
	q += " ORDER BY random() LIMIT 1"
	if err := o.pool.QueryRow(ctx, q, args...).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("%w for region %q", ErrNoScannerNode, region)
	}
	return id, nil
}

// recordFailover writes one row per cross-region pick. Read by ops
// dashboards + the scanner_region_failover_total Prometheus counter
// (vaultscan_scanner_region_failover_total{from,to}).
func (o *Orchestrator) recordFailover(ctx context.Context, from, to string) {
	_, _ = o.pool.Exec(ctx, `
		INSERT INTO scanner_failover_attempts(from_region, to_region, decided_at)
		VALUES ($1, $2, now())
		ON CONFLICT DO NOTHING`, from, to)
	observability.ScanJobsCreated.WithLabelValues("region_failover").Inc()
}

// isNoNodeErr reports whether err is the "no scanner node available"
// case (used by pickScannerNode to decide whether to walk the
// failover ladder vs surface a hard infra error).
// isUniqueViolation reports whether err is a Postgres unique-
// constraint violation (SQLSTATE 23505). Used by Submit() to map
// a race-loser INSERT against scan_jobs_tenant_idempotency_key_idx
// into a "return the existing job" idempotency response.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func isNoNodeErr(err error) bool {
	return errors.Is(err, ErrNoScannerNode)
}

func summarizeTargets(t []string) string {
	if len(t) == 0 {
		return ""
	}
	if len(t) == 1 {
		return t[0]
	}
	return fmt.Sprintf("%s (+%d more)", t[0], len(t)-1)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func detectTargetType(t string) string {
	if isCIDR(t) {
		return "cidr"
	}
	if isIP(t) {
		return "ip"
	}
	if hasURLScheme(t) {
		return "url"
	}
	return "domain"
}

// quick helpers (small surface to avoid extra deps)
func isIP(t string) bool {
	return countDots(t) == 3 && allDigitsOrDot(t)
}
func isCIDR(t string) bool { return containsRune(t, '/') && isIPish(beforeSlash(t)) }
func hasURLScheme(t string) bool {
	return len(t) > 7 && (t[:7] == "http://" || (len(t) > 8 && t[:8] == "https://"))
}
func countDots(s string) int {
	n := 0
	for _, c := range s {
		if c == '.' {
			n++
		}
	}
	return n
}
func allDigitsOrDot(s string) bool {
	for _, c := range s {
		if !(c == '.' || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
func beforeSlash(s string) string {
	for i, c := range s {
		if c == '/' {
			return s[:i]
		}
	}
	return s
}
func isIPish(s string) bool { return countDots(s) == 3 && allDigitsOrDot(s) }

// -- Signer ----------------------------------------------------------------

// Signer signs scan job manifests with an RSA private key, satisfying the
// "no agent executes unsigned jobs" rule (Blueprint §11.3, §13.5).
type Signer struct {
	keyID  string
	priv   *rsa.PrivateKey
}

// NewSigner returns a signer. If pemKey is empty a fresh ephemeral key is
// generated (acceptable for development).
func NewSigner(keyID, pemKey string) (*Signer, error) {
	if pemKey == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return &Signer{keyID: keyID, priv: key}, nil
	}
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("scanorch: signer pem decode failed")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		k2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("scanorch: parse signing key: %w", err)
		}
		var ok bool
		key, ok = k2.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("scanorch: signing key must be RSA")
		}
	}
	return &Signer{keyID: keyID, priv: key}, nil
}

func (s *Signer) KeyID() string { return s.keyID }

func (s *Signer) Sign(payload []byte) (string, error) {
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// PublicKeyPEM returns the PEM-encoded SubjectPublicKeyInfo for distribution
// to agents and scanner nodes.
func (s *Signer) PublicKeyPEM() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(pemBytes), nil
}

// CanonicalManifest returns the byte sequence that MUST be hashed and signed
// by the orchestrator AND independently reconstructed by every scanner
// worker / agent prior to executing the job. Keep it deterministic: every
// field must be present in the scan_jobs row so verification is possible
// after process restart or in a fresh worker.
//
// Key ordering is alphabetical because that's what Go's json.Marshal does
// for map[string]any, and we deliberately rely on that property here.
func CanonicalManifest(
	jobID, tenantID, engagementID uuid.UUID,
	profileCode, plane string,
	agentID *uuid.UUID,
	tools, targets []string,
) []byte {
	manifest, _ := json.Marshal(map[string]any{
		"agent_id":      agentID,
		"engagement_id": engagementID,
		"job_id":        jobID,
		"plane":         plane,
		"profile":       profileCode,
		"targets":       targets,
		"tenant_id":     tenantID,
		"tools":         tools,
	})
	return manifest
}

// VerifyExternal allows agents (in-process tests) to validate a signature.
func VerifyExternal(pubPEM string, payload []byte, sigB64 string) error {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return errors.New("scanorch: bad public key pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("scanorch: public key not RSA")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig)
}

// keep imports referenced
var _ = fnv.New32
