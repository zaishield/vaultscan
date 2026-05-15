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
)

type Service struct {
	pool     *pgxpool.Pool
	audit    *audit.Service
	bus      *eventbus.Bus
	findings *findings.Service
}

func New(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus, f *findings.Service) *Service {
	return &Service{pool: pool, audit: a, bus: b, findings: f}
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
		PlatformID: f.PartnerID, PartnerID: &f.PartnerID, TenantID: &f.TenantID,
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
			PlatformID: f.PartnerID, PartnerID: &f.PartnerID, TenantID: &f.TenantID,
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
