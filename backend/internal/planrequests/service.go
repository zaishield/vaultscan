// Package planrequests is the customer-facing path for plan
// upgrades / downgrades. Customer admin files a request → sales /
// finance reviews → operator applies the actual plan change.
//
// Removes the "email your CSM and wait days" loop: requests are
// trackable, audited, and visible to both parties.

package planrequests

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusRejected  = "rejected"
	StatusCancelled = "cancelled"
)

type Request struct {
	ID            uuid.UUID  `json:"id"`
	PartnerID     uuid.UUID  `json:"partner_id"`
	RequestedBy   uuid.UUID  `json:"requested_by"`
	CurrentPlan   string     `json:"current_plan"`
	RequestedPlan string     `json:"requested_plan"`
	Note          string     `json:"note,omitempty"`
	Status        string     `json:"status"`
	RequestedAt   time.Time  `json:"requested_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	DecidedBy     *uuid.UUID `json:"decided_by,omitempty"`
	DecisionNote  string     `json:"decision_note,omitempty"`
}

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

// File opens a new plan-change request. The customer admin calls
// this; operators see it in their queue.
func (s *Service) File(ctx context.Context, partnerID, requester uuid.UUID,
	currentPlan, requestedPlan, note string,
) (*Request, error) {
	if requestedPlan == "" || requestedPlan == currentPlan {
		return nil, errors.New("planrequests: requested_plan must differ from current_plan")
	}
	id := uuid.New()
	now := time.Now().UTC()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO plan_change_requests(id, partner_id, requested_by,
		    current_plan, requested_plan, note, status, requested_at)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), 'pending', $7)`,
		id, partnerID, requester, currentPlan, requestedPlan, note, now); err != nil {
		return nil, fmt.Errorf("planrequests: insert: %w", err)
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Event:    "partner.plan_change_requested",
		ActorID:  &requester,
		Payload: map[string]any{
			"request_id":     id,
			"partner_id":     partnerID,
			"current_plan":   currentPlan,
			"requested_plan": requestedPlan,
		},
	})
	return &Request{
		ID: id, PartnerID: partnerID, RequestedBy: requester,
		CurrentPlan: currentPlan, RequestedPlan: requestedPlan,
		Note: note, Status: StatusPending, RequestedAt: now,
	}, nil
}

// Decide closes a request as approved or rejected. Applies the
// actual plan change ONLY when status=approved AND apply=true (so
// the operator can approve-pending-billing-confirmation).
//
// When apply=true + approved, records the transition in
// partner_plan_history. The actual `partners.plan` update is the
// caller's responsibility (we don't reach into that table here so
// the existing billing service stays the canonical mutator).
func (s *Service) Decide(ctx context.Context, requestID, deciderID uuid.UUID,
	status string, note string,
) (*Request, error) {
	switch status {
	case StatusApproved, StatusRejected, StatusCancelled:
	default:
		return nil, errors.New("planrequests: status must be approved | rejected | cancelled")
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE plan_change_requests
		   SET status = $2, decided_at = now(), decided_by = $3,
		       decision_note = NULLIF($4,'')
		 WHERE id = $1 AND status = 'pending'`,
		requestID, status, deciderID, note); err != nil {
		return nil, fmt.Errorf("planrequests: decide: %w", err)
	}
	r, err := s.Get(ctx, requestID)
	if err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Event:    "partner.plan_change_decided",
		ActorID:  &deciderID,
		Payload: map[string]any{
			"request_id": requestID, "status": status, "note": note,
		},
	})
	return r, nil
}

// RecordTransition logs a partner plan transition. Called by both
// (a) the approval path here AND (b) the operator-initiated
// putBillingPlan handler (which bypasses the request flow for
// platform-admin-driven changes).
func (s *Service) RecordTransition(ctx context.Context, partnerID uuid.UUID,
	fromPlan, toPlan string, changedBy uuid.UUID, requestID *uuid.UUID, note string,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO partner_plan_history(partner_id, from_plan, to_plan,
		    changed_at, changed_by, request_id, note)
		VALUES ($1, NULLIF($2,''), $3, now(), $4, $5, NULLIF($6,''))`,
		partnerID, fromPlan, toPlan, changedBy, requestID, note)
	if err != nil {
		return fmt.Errorf("planrequests: history: %w", err)
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Event:   "partner.plan_changed",
		ActorID: &changedBy,
		Payload: map[string]any{
			"partner_id": partnerID,
			"from_plan":  fromPlan,
			"to_plan":    toPlan,
			"request_id": requestID,
		},
	})
	return nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Request, error) {
	var r Request
	err := s.pool.QueryRow(ctx, `
		SELECT id, partner_id, requested_by, current_plan, requested_plan,
		       COALESCE(note,''), status, requested_at, decided_at, decided_by,
		       COALESCE(decision_note,'')
		  FROM plan_change_requests WHERE id = $1`, id).
		Scan(&r.ID, &r.PartnerID, &r.RequestedBy, &r.CurrentPlan,
			&r.RequestedPlan, &r.Note, &r.Status, &r.RequestedAt,
			&r.DecidedAt, &r.DecidedBy, &r.DecisionNote)
	if err != nil {
		return nil, fmt.Errorf("planrequests: read: %w", err)
	}
	return &r, nil
}

// ListForPartner returns the partner's plan-change request history,
// newest first. Used by customer admins to track their own requests.
func (s *Service) ListForPartner(ctx context.Context, partnerID uuid.UUID, limit int) ([]Request, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, partner_id, requested_by, current_plan, requested_plan,
		       COALESCE(note,''), status, requested_at, decided_at, decided_by,
		       COALESCE(decision_note,'')
		  FROM plan_change_requests
		 WHERE partner_id = $1
		 ORDER BY requested_at DESC LIMIT $2`, partnerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		var r Request
		if err := rows.Scan(&r.ID, &r.PartnerID, &r.RequestedBy, &r.CurrentPlan,
			&r.RequestedPlan, &r.Note, &r.Status, &r.RequestedAt, &r.DecidedAt,
			&r.DecidedBy, &r.DecisionNote); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ListPending returns every pending request across all partners.
// For the platform-admin / sales-ops queue view.
func (s *Service) ListPending(ctx context.Context) ([]Request, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, partner_id, requested_by, current_plan, requested_plan,
		       COALESCE(note,''), status, requested_at, decided_at, decided_by,
		       COALESCE(decision_note,'')
		  FROM plan_change_requests
		 WHERE status = 'pending'
		 ORDER BY requested_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		var r Request
		if err := rows.Scan(&r.ID, &r.PartnerID, &r.RequestedBy, &r.CurrentPlan,
			&r.RequestedPlan, &r.Note, &r.Status, &r.RequestedAt, &r.DecidedAt,
			&r.DecidedBy, &r.DecisionNote); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
