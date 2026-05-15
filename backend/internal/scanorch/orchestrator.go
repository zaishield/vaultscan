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
	"hash/fnv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
)

type Orchestrator struct {
	pool      *pgxpool.Pool
	guard     *scopeguard.Service
	audit     *audit.Service
	bus       *eventbus.Bus
	signer    *Signer
}

func New(pool *pgxpool.Pool, g *scopeguard.Service, a *audit.Service, b *eventbus.Bus, s *Signer) *Orchestrator {
	return &Orchestrator{pool: pool, guard: g, audit: a, bus: b, signer: s}
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
}

// Submit performs Scope Guard evaluation, persists the job, signs it, and
// (if approved) dispatches to scanner farm or agent queue.
func (o *Orchestrator) Submit(ctx context.Context, in SubmitInput) (*models.ScanJob, *scopeguard.Decision, error) {
	if len(in.Targets) == 0 {
		return nil, nil, errors.New("scanorch: at least one target required")
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

	// Sign the job manifest.
	manifest, _ := json.Marshal(map[string]any{
		"job_id": job.ID, "tenant_id": job.TenantID, "engagement_id": job.EngagementID,
		"profile": prof.Code, "tools": prof.Tools, "targets": in.Targets,
		"plane": job.Plane, "agent_id": in.AgentID, "issued_at": time.Now().UTC(),
	})
	sig, err := o.signer.Sign(manifest)
	if err != nil {
		return nil, nil, err
	}
	job.JobSignature = sig

	targetsJSON, _ := json.Marshal(in.Targets)
	if err := o.pool.QueryRow(ctx, `
		INSERT INTO scan_jobs(id, platform_id, partner_id, tenant_id, engagement_id, profile_id,
		    plane, region, agent_id, scanner_node_id, status, target_summary, targets,
		    schedule_at, requires_approval, job_signature, signing_key_id, requested_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18)
		RETURNING created_at`,
		job.ID, job.PlatformID, job.PartnerID, job.TenantID, job.EngagementID, job.ProfileID,
		job.Plane, nullIfEmpty(job.Region), job.AgentID, job.ScannerNodeID, job.Status,
		job.TargetSummary, targetsJSON, job.ScheduleAt, job.RequiresApproval,
		job.JobSignature, job.SigningKeyID, job.RequestedBy,
	).Scan(&job.CreatedAt); err != nil {
		return nil, nil, fmt.Errorf("scanorch: insert scan_job: %w", err)
	}

	// Materialize per-tool tasks.
	for _, tool := range prof.Tools {
		taskID := uuid.New()
		_, err := o.pool.Exec(ctx, `
			INSERT INTO scan_tasks(id, scan_job_id, tool, image_ref, status,
			    cpu_limit, memory_limit, runtime_limit_s)
			VALUES ($1,$2,$3,$4,'queued','2','4Gi',1800)`,
			taskID, job.ID, tool, "registry.zaishield.com/vaultscan/scanners/"+tool+":latest")
		if err != nil {
			return nil, nil, err
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

	if !job.RequiresApproval {
		if _, err := o.Approve(ctx, job.ID, in.RequestedBy); err != nil {
			return nil, nil, err
		}
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
// emits the EmergencyStopTriggered event.
func (o *Orchestrator) EmergencyStop(ctx context.Context, actor *uuid.UUID, scope EmergencyScope) (int, error) {
	var args []any
	q := `UPDATE scan_jobs SET status='stopped', cancellation_reason=$1, updated_at=now()
	       WHERE status IN ('pending','approved','dispatched','running')`
	args = append(args, "emergency_stop")
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
	}
	return count, rows.Err()
}

type EmergencyScope struct {
	JobID    *uuid.UUID
	TenantID *uuid.UUID
	AgentID  *uuid.UUID
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

func (o *Orchestrator) pickScannerNode(ctx context.Context, region string) (uuid.UUID, error) {
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
		return uuid.Nil, fmt.Errorf("scanorch: no scanner node available for region %q", region)
	}
	return id, nil
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
