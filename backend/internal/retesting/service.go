// Package retesting closes the remediation loop (Blueprint §17.3, §33.2).
package retesting

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

type Service struct {
	pool     *pgxpool.Pool
	audit    *audit.Service
	bus      *eventbus.Bus
	findings *findings.Service
	orch     *scanorch.Orchestrator
}

func New(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus, f *findings.Service, orch *scanorch.Orchestrator) *Service {
	return &Service{pool: pool, audit: a, bus: b, findings: f, orch: orch}
}

type RequestInput struct {
	FindingID    uuid.UUID
	RequestedBy  *uuid.UUID
	Note         string
}

func (s *Service) Request(ctx context.Context, in RequestInput) (uuid.UUID, error) {
	f, err := s.findings.Get(ctx, in.FindingID)
	if err != nil {
		return uuid.Nil, err
	}
	if f.Status != "remediated" && f.Status != "open" && f.Status != "in_progress" {
		return uuid.Nil, fmt.Errorf("retesting: finding must be remediated/open/in_progress (was %s)", f.Status)
	}
	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO retest_requests(id, finding_id, requested_by, note, status)
		VALUES ($1,$2,$3,$4,'pending')`, id, in.FindingID, in.RequestedBy, in.Note); err != nil {
		return uuid.Nil, err
	}
	if err := s.findings.Transition(ctx, in.RequestedBy, in.FindingID, "retest_requested",
		"retest queued: "+in.Note); err != nil {
		// already in retest_requested is acceptable
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: f.PlatformID, PartnerID: &f.PartnerID, TenantID: &f.TenantID,
		ActorID: in.RequestedBy, Event: audit.EventRetestRequested,
		TargetType: "retest_request", TargetID: id.String(),
		Payload: map[string]any{"finding_id": in.FindingID},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.RetestRequested, TenantID: &f.TenantID, PartnerID: &f.PartnerID,
		ActorID: in.RequestedBy, Payload: map[string]any{"retest_id": id, "finding_id": in.FindingID},
	})
	return id, nil
}

func (s *Service) Assign(ctx context.Context, retestID, assignee uuid.UUID, assignedBy *uuid.UUID) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO retest_assignments(retest_request_id, assignee_id, assigned_by)
		VALUES ($1,$2,$3)`, retestID, assignee, assignedBy); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE retest_requests SET status='assigned' WHERE id=$1 AND status='pending'`, retestID)
	return err
}

type ResultInput struct {
	RetestRequestID uuid.UUID
	ScanJobID       *uuid.UUID
	Outcome         string  // passed | failed
	Summary         string
	DecidedBy       *uuid.UUID
}

func (s *Service) RecordResult(ctx context.Context, in ResultInput) error {
	if in.Outcome != "passed" && in.Outcome != "failed" {
		return errors.New("retesting: outcome must be passed|failed")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO retest_results(retest_request_id, scan_job_id, outcome, summary, decided_by)
		VALUES ($1,$2,$3,$4,$5)`,
		in.RetestRequestID, in.ScanJobID, in.Outcome, in.Summary, in.DecidedBy); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE retest_requests SET status=$2, decided_at=now() WHERE id=$1`,
		in.RetestRequestID, in.Outcome); err != nil {
		return err
	}
	var findingID uuid.UUID
	_ = tx.QueryRow(ctx, `SELECT finding_id FROM retest_requests WHERE id=$1`,
		in.RetestRequestID).Scan(&findingID)
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	to := "retest_passed"
	event := audit.EventRetestPassed
	busEvent := eventbus.RetestPassed
	if in.Outcome == "failed" {
		to = "retest_failed"
		event = audit.EventRetestFailed
		busEvent = eventbus.RetestFailed
	}
	_ = s.findings.Transition(ctx, in.DecidedBy, findingID, to, in.Summary)

	f, _ := s.findings.Get(ctx, findingID)
	if f != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			PlatformID: f.PlatformID, PartnerID: &f.PartnerID, TenantID: &f.TenantID,
			ActorID: in.DecidedBy, Event: event,
			TargetType: "retest_request", TargetID: in.RetestRequestID.String(),
			Payload: map[string]any{"finding_id": findingID, "outcome": in.Outcome},
		})
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type: busEvent, TenantID: &f.TenantID, PartnerID: &f.PartnerID,
			ActorID: in.DecidedBy,
			Payload: map[string]any{"retest_id": in.RetestRequestID, "finding_id": findingID},
		})
	}
	return nil
}

func (s *Service) ListByFinding(ctx context.Context, findingID uuid.UUID) ([]Item, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.finding_id, r.status, r.requested_by, r.requested_at,
		       r.decided_at, COALESCE(rs.outcome,''), COALESCE(rs.summary,'')
		  FROM retest_requests r
		  LEFT JOIN retest_results rs ON rs.retest_request_id = r.id
		 WHERE r.finding_id=$1
		 ORDER BY r.requested_at DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.FindingID, &it.Status, &it.RequestedBy,
			&it.RequestedAt, &it.DecidedAt, &it.Outcome, &it.Summary); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

type Item struct {
	ID          uuid.UUID  `json:"id"`
	FindingID   uuid.UUID  `json:"finding_id"`
	Status      string     `json:"status"`
	RequestedBy *uuid.UUID `json:"requested_by,omitempty"`
	RequestedAt any        `json:"requested_at"`
	DecidedAt   any        `json:"decided_at,omitempty"`
	Outcome     string     `json:"outcome,omitempty"`
	Summary     string     `json:"summary,omitempty"`
}

// LaunchScan materialises a targeted scan job from a retest request: same
// scanner, same endpoint, same engagement. Blueprint §17.3 / VS-09 mandates
// the retest is scoped strictly to the original endpoint — broader scans are
// not permitted. The new job is linked back via retest_requests.scan_job_id.
//
// Returns the new job id. The scanner worker will pick it up on its next
// poll; when the worker reports succeeded/failed, the caller (or a
// retest-decision worker) maps the result to RecordResult().
func (s *Service) LaunchScan(ctx context.Context, retestID uuid.UUID, actor *uuid.UUID) (uuid.UUID, error) {
	if s.orch == nil {
		return uuid.Nil, errors.New("retesting: orchestrator not wired")
	}

	// Pull the finding the retest is targeting so we can rebuild a
	// pinpoint scan: same tenant/engagement, same scanner/profile, same
	// affected endpoint.
	var (
		findingID                                     uuid.UUID
		tenantID, partnerID, engagementID, platformID uuid.UUID
		scanner, scanType, endpoint                   string
		port                                          int
	)
	// NB: an earlier version of this query joined scan_profiles to
	// pick a plane via CASE, but both branches returned 'external'
	// AND the joined plane was never read by the caller — the
	// authoritative plane is derived from profileForScanner(scanner)
	// below. The buggy CASE/JOIN was removed in 2026-05 as part of
	// the audit cleanup.
	if err := s.pool.QueryRow(ctx, `
		SELECT f.id, f.tenant_id, f.partner_id, f.engagement_id, f.platform_id,
		       f.scanner, f.scan_type, COALESCE(f.affected_endpoint, ''), COALESCE(f.port, 0)
		  FROM retest_requests r
		  JOIN findings f ON f.id = r.finding_id
		 WHERE r.id = $1`, retestID).
		Scan(&findingID, &tenantID, &partnerID, &engagementID, &platformID,
			&scanner, &scanType, &endpoint, &port); err != nil {
		return uuid.Nil, fmt.Errorf("retesting: locate finding: %w", err)
	}
	if endpoint == "" {
		return uuid.Nil, errors.New("retesting: finding has no affected_endpoint to retest")
	}

	// Pick the scan profile that matches the original scanner. We use the
	// "standard" profile for that scanner's plane.
	profileCode, profilePlane := profileForScanner(scanner)

	job, decision, err := s.orch.Submit(ctx, scanorch.SubmitInput{
		PlatformID:   platformID,
		PartnerID:    partnerID,
		TenantID:     tenantID,
		EngagementID: engagementID,
		ProfileCode:  profileCode,
		Plane:        profilePlane,
		Region:       "ae", // default region; caller can override later
		Targets:      []string{endpoint},
		RequestedBy:  actor,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("retesting: submit scan: %w", err)
	}
	if job == nil {
		if decision != nil {
			return uuid.Nil, fmt.Errorf("retesting: scope guard refused retest: %s (%s)",
				decision.Code, decision.Reason)
		}
		return uuid.Nil, errors.New("retesting: orchestrator returned no job")
	}

	if _, err := s.pool.Exec(ctx,
		`UPDATE retest_requests SET scan_job_id=$2, status='in_progress'
		 WHERE id=$1`, retestID, job.ID); err != nil {
		return uuid.Nil, err
	}

	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: "retest.scan_launched",
		TargetType: "retest_request", TargetID: retestID.String(),
		Payload: map[string]any{"scan_job_id": job.ID, "finding_id": findingID,
			"endpoint": endpoint, "profile": profileCode},
	})
	return job.ID, nil
}

// profileForScanner maps the original scanner name to the scan profile we
// should re-run for a retest.
func profileForScanner(scanner string) (code, plane string) {
	switch scanner {
	case "zap", "nuclei", "katana", "ffuf":
		return "external_web_va", "external"
	case "testssl", "sslyze":
		return "external_tls_review", "external"
	case "nmap", "openvas", "naabu":
		return "external_standard_va", "external"
	case "bloodhound", "netexec":
		return "internal_ad_review", "internal"
	case "lynis":
		return "internal_linux_hardening", "internal"
	case "trivy", "grype":
		return "internal_container_review", "internal"
	case "kube-bench", "kube-hunter":
		return "internal_k8s_review", "internal"
	case "prowler", "scoutsuite":
		return "cloud_posture", "external"
	default:
		return "external_standard_va", "external"
	}
}

// PendingForUser returns retest requests assigned to (or unassigned and
// available to) the given user. Powers the pentester's "retest queue" UI.
func (s *Service) PendingForUser(ctx context.Context, userID uuid.UUID) ([]Item, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.finding_id, r.status, r.requested_by, r.requested_at,
		       r.decided_at, '', ''
		  FROM retest_requests r
		  LEFT JOIN retest_assignments a ON a.retest_request_id = r.id
		 WHERE r.status IN ('pending','assigned','in_progress')
		   AND (a.assignee_id = $1 OR a.id IS NULL)
		 ORDER BY r.requested_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.FindingID, &it.Status, &it.RequestedBy,
			&it.RequestedAt, &it.DecidedAt, &it.Outcome, &it.Summary); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
