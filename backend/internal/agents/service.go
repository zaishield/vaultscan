// Package agents implements internal-agent enrollment, heartbeats, policies,
// and the cloud-side mTLS verification (Blueprint §13, §28).
package agents

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
	bus   *eventbus.Bus
}

func New(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus) *Service {
	return &Service{pool: pool, audit: a, bus: b}
}

type CreateInput struct {
	PlatformID uuid.UUID
	PartnerID  uuid.UUID
	TenantID   uuid.UUID
	Name       string
	Location   string
	FormFactor string
	CreatedBy  *uuid.UUID
}

// Provision creates a placeholder agent record + a one-time enrollment token.
func (s *Service) Provision(ctx context.Context, in CreateInput) (*models.Agent, string, error) {
	if in.Name == "" {
		return nil, "", errors.New("agents: name required")
	}
	if in.FormFactor == "" {
		in.FormFactor = "linux_vm"
	}
	a := &models.Agent{
		ID: uuid.New(), PlatformID: in.PlatformID, PartnerID: in.PartnerID,
		TenantID: in.TenantID, Name: in.Name, Location: in.Location,
		FormFactor: in.FormFactor, Status: "pending",
		CertStatus: "none", EmergencyStopArmed: true,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `
		INSERT INTO agents(id, platform_id, partner_id, tenant_id, name, location,
		    form_factor, status, cert_status, emergency_stop_armed, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at`,
		a.ID, a.PlatformID, a.PartnerID, a.TenantID, a.Name,
		nullIfEmpty(a.Location), a.FormFactor, a.Status, a.CertStatus,
		a.EmergencyStopArmed, in.CreatedBy).Scan(&a.CreatedAt); err != nil {
		return nil, "", fmt.Errorf("agents: insert: %w", err)
	}

	// Default agent policy.
	if _, err := tx.Exec(ctx, `INSERT INTO agent_policies(agent_id) VALUES ($1)`, a.ID); err != nil {
		return nil, "", err
	}

	tokenRaw := newToken()
	hash, err := bcrypt.GenerateFromPassword([]byte(tokenRaw), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens(agent_id, token_hash, issued_by, expires_at)
		VALUES ($1,$2,$3, now() + INTERVAL '24 hours')`,
		a.ID, string(hash), in.CreatedBy); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return a, tokenRaw, nil
}

// Enroll consumes a one-time token and binds an agent's certificate.
func (s *Service) Enroll(ctx context.Context, agentID uuid.UUID, token, certPEM, fingerprint string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var (
		hash       string
		expiresAt  time.Time
		consumedAt *time.Time
		tokID      uuid.UUID
	)
	err = tx.QueryRow(ctx, `
		SELECT id, token_hash, expires_at, consumed_at
		  FROM agent_enrollment_tokens
		 WHERE agent_id=$1 AND consumed_at IS NULL
		 ORDER BY issued_at DESC LIMIT 1`, agentID).
		Scan(&tokID, &hash, &expiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("agents: no enrollment token found")
	}
	if err != nil {
		return err
	}
	if time.Now().After(expiresAt) {
		return errors.New("agents: token expired")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)); err != nil {
		return errors.New("agents: invalid token")
	}
	serial := newToken()[:16]
	exp := time.Now().UTC().Add(365 * 24 * time.Hour)
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_certificates(agent_id, serial, fingerprint, pem, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		agentID, serial, fingerprint, certPEM, exp); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents
		   SET status='online', cert_status='issued', cert_expires_at=$2,
		       updated_at=now(), last_heartbeat=now()
		 WHERE id=$1`, agentID, exp); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_enrollment_tokens SET consumed_at=now() WHERE id=$1`, tokID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	a, _ := s.Get(ctx, agentID)
	if a != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: a.PlatformID, PartnerID: &a.PartnerID, TenantID: &a.TenantID,
			ActorType: "agent", Event: audit.EventAgentEnrolled,
			TargetType: "agent", TargetID: agentID.String(),
			Payload: map[string]any{"fingerprint": fingerprint, "expires_at": exp},
		})
	}
	return nil
}

type Heartbeat struct {
	AgentID         uuid.UUID
	CPUPercent      float64
	MemoryPercent   float64
	DiskPercent     float64
	RunningJobs     int
	QueueDepth      int
	Version         string
	Payload         map[string]any
}

func (s *Service) Heartbeat(ctx context.Context, hb Heartbeat) error {
	payload, _ := json.Marshal(hb.Payload)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_heartbeats(agent_id, cpu_percent, memory_percent, disk_percent,
		    running_jobs, queue_depth, version, payload)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
		hb.AgentID, hb.CPUPercent, hb.MemoryPercent, hb.DiskPercent,
		hb.RunningJobs, hb.QueueDepth, nullIfEmpty(hb.Version), payload); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents
		   SET status='online', last_heartbeat=now(), cpu_percent=$2,
		       memory_percent=$3, version=COALESCE($4, version)
		 WHERE id=$1`,
		hb.AgentID, hb.CPUPercent, hb.MemoryPercent, nullIfEmpty(hb.Version)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	a, _ := s.Get(ctx, hb.AgentID)
	if a != nil {
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.AgentHeartbeatReceived, TenantID: &a.TenantID, PartnerID: &a.PartnerID,
			Payload: map[string]any{"agent_id": hb.AgentID, "cpu": hb.CPUPercent, "mem": hb.MemoryPercent},
		})
	}
	return nil
}

// PollJobs returns up to n queued jobs for the agent, marking them dispatched.
func (s *Service) PollJobs(ctx context.Context, agentID uuid.UUID, n int) ([]models.ScanJob, error) {
	if n <= 0 || n > 5 {
		n = 1
	}
	rows, err := s.pool.Query(ctx, `
		WITH cte AS (
		  SELECT id FROM agent_job_queue
		   WHERE agent_id=$1 AND state='queued'
		   ORDER BY enqueued_at LIMIT $2
		)
		UPDATE agent_job_queue q
		   SET state='dispatched', dispatched_at=now()
		  FROM cte WHERE q.id = cte.id
		RETURNING q.scan_job_id`, agentID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		jobIDs = append(jobIDs, id)
	}
	out := make([]models.ScanJob, 0, len(jobIDs))
	for _, id := range jobIDs {
		row := s.pool.QueryRow(ctx, `
			SELECT j.id, j.platform_id, j.partner_id, j.tenant_id, j.engagement_id, j.profile_id,
			       p.code, j.plane, COALESCE(j.region,''), j.agent_id, j.scanner_node_id, j.status,
			       j.target_summary, j.targets, j.requires_approval,
			       COALESCE(j.job_signature,''), COALESCE(j.signing_key_id,''),
			       j.requested_by, j.created_at
			  FROM scan_jobs j JOIN scan_profiles p ON p.id = j.profile_id
			 WHERE j.id=$1`, id)
		var j models.ScanJob
		var targetsJSON []byte
		if err := row.Scan(&j.ID, &j.PlatformID, &j.PartnerID, &j.TenantID, &j.EngagementID,
			&j.ProfileID, &j.ProfileCode, &j.Plane, &j.Region, &j.AgentID, &j.ScannerNodeID,
			&j.Status, &j.TargetSummary, &targetsJSON, &j.RequiresApproval,
			&j.JobSignature, &j.SigningKeyID, &j.RequestedBy, &j.CreatedAt); err != nil {
			continue
		}
		_ = json.Unmarshal(targetsJSON, &j.Targets)
		// Hydrate j.Tools from scan_profiles.tools — that's the SAME
		// JSON the orchestrator passed into CanonicalManifest, so the
		// agent can rebuild a byte-identical manifest for signature
		// verification. Using scan_tasks here would reorder tools
		// alphabetically and break the signature match.
		var profileToolsJSON []byte
		if err := s.pool.QueryRow(ctx,
			`SELECT p.tools FROM scan_jobs j JOIN scan_profiles p ON p.id=j.profile_id
			 WHERE j.id=$1`, id).Scan(&profileToolsJSON); err == nil {
			_ = json.Unmarshal(profileToolsJSON, &j.Tools)
		}
		out = append(out, j)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Agent, error) {
	a := &models.Agent{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, platform_id, partner_id, tenant_id, name, COALESCE(location,''),
		       form_factor, COALESCE(version,''), status, last_heartbeat,
		       COALESCE(cpu_percent, 0), COALESCE(memory_percent, 0),
		       cert_status, cert_expires_at, emergency_stop_armed, created_at
		  FROM agents WHERE id=$1`, id).
		Scan(&a.ID, &a.PlatformID, &a.PartnerID, &a.TenantID, &a.Name, &a.Location,
			&a.FormFactor, &a.Version, &a.Status, &a.LastHeartbeat,
			&a.CPUPercent, &a.MemoryPercent, &a.CertStatus, &a.CertExpiresAt,
			&a.EmergencyStopArmed, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Service) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, platform_id, partner_id, tenant_id, name, COALESCE(location,''),
		       form_factor, COALESCE(version,''), status, last_heartbeat,
		       COALESCE(cpu_percent, 0), COALESCE(memory_percent, 0),
		       cert_status, cert_expires_at, emergency_stop_armed, created_at
		  FROM agents WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Agent
	for rows.Next() {
		var a models.Agent
		if err := rows.Scan(&a.ID, &a.PlatformID, &a.PartnerID, &a.TenantID, &a.Name, &a.Location,
			&a.FormFactor, &a.Version, &a.Status, &a.LastHeartbeat,
			&a.CPUPercent, &a.MemoryPercent, &a.CertStatus, &a.CertExpiresAt,
			&a.EmergencyStopArmed, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Policy(ctx context.Context, agentID uuid.UUID) (*models.AgentPolicy, error) {
	p := &models.AgentPolicy{AgentID: agentID}
	var allowed, blocked, profiles, tools, dows []byte
	var startStr, endStr *string
	var tenantID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT a.tenant_id, p.allowed_scopes, p.blocked_scopes, p.allowed_scan_profiles,
		       p.allowed_tools, p.max_concurrent_jobs, p.max_cpu_percent, p.max_memory_percent,
		       to_char(p.scan_window_start, 'HH24:MI'), to_char(p.scan_window_end, 'HH24:MI'),
		       p.days_of_week, p.emergency_stop_enabled
		  FROM agent_policies p
		  JOIN agents a ON a.id = p.agent_id
		 WHERE p.agent_id=$1`, agentID).
		Scan(&tenantID, &allowed, &blocked, &profiles, &tools,
			&p.MaxConcurrentJobs, &p.MaxCPUPercent, &p.MaxMemoryPercent,
			&startStr, &endStr, &dows, &p.EmergencyStopEnabled)
	if err != nil {
		return nil, err
	}
	p.TenantID = tenantID
	_ = json.Unmarshal(allowed, &p.AllowedScopes)
	_ = json.Unmarshal(blocked, &p.BlockedScopes)
	_ = json.Unmarshal(profiles, &p.AllowedScanProfiles)
	_ = json.Unmarshal(tools, &p.AllowedTools)
	_ = json.Unmarshal(dows, &p.DaysOfWeek)
	if startStr != nil {
		p.ScanWindowStart = *startStr
	}
	if endStr != nil {
		p.ScanWindowEnd = *endStr
	}
	return p, nil
}

func (s *Service) UpdatePolicy(ctx context.Context, agentID uuid.UUID, p models.AgentPolicy) error {
	allowed, _ := json.Marshal(p.AllowedScopes)
	blocked, _ := json.Marshal(p.BlockedScopes)
	profiles, _ := json.Marshal(p.AllowedScanProfiles)
	tools, _ := json.Marshal(p.AllowedTools)
	dows, _ := json.Marshal(p.DaysOfWeek)
	_, err := s.pool.Exec(ctx, `
		UPDATE agent_policies SET
		    allowed_scopes        = $2::jsonb,
		    blocked_scopes        = $3::jsonb,
		    allowed_scan_profiles = $4::jsonb,
		    allowed_tools         = $5::jsonb,
		    max_concurrent_jobs   = $6,
		    max_cpu_percent       = $7,
		    max_memory_percent    = $8,
		    scan_window_start     = NULLIF($9,'')::time,
		    scan_window_end       = NULLIF($10,'')::time,
		    days_of_week          = $11::jsonb,
		    emergency_stop_enabled= $12,
		    updated_at = now()
		 WHERE agent_id=$1`,
		agentID, allowed, blocked, profiles, tools,
		p.MaxConcurrentJobs, p.MaxCPUPercent, p.MaxMemoryPercent,
		p.ScanWindowStart, p.ScanWindowEnd, dows, p.EmergencyStopEnabled)
	return err
}

// IssueRotationToken creates a fresh enrollment token bound to an existing
// agent. Used by /api/v1/agents/{id}/rotate-cert so the operator doesn't have
// to re-provision the entire agent record.
func IssueRotationToken(ctx context.Context, pool *pgxpool.Pool, agentID uuid.UUID, issuedBy *uuid.UUID) (string, error) {
	raw := newToken()
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens(agent_id, token_hash, issued_by, expires_at)
		VALUES ($1, $2, $3, now() + INTERVAL '24 hours')`,
		agentID, string(hash), issuedBy); err != nil {
		return "", err
	}
	return raw, nil
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
