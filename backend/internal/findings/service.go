// Package findings is the canonical vulnerability management engine
// (Blueprint §17). It normalizes raw scanner output into the canonical
// model, deduplicates by the 9-field key, and tracks the 11 lifecycle
// states.
package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
	"github.com/zaishield/vaultscan/backend/internal/observability"
)

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
	bus   *eventbus.Bus
}

func New(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus) *Service {
	return &Service{pool: pool, audit: a, bus: b}
}

// ValidStatuses returns the 11 lifecycle states from Blueprint §17.3.
func ValidStatuses() []string { return models.FindingStatuses }

// AllowedTransitions enforces the lifecycle state machine.
var AllowedTransitions = map[string]map[string]bool{
	"open":              setOf("triaged", "assigned", "false_positive", "risk_accepted", "closed"),
	"triaged":           setOf("assigned", "in_progress", "false_positive", "risk_accepted", "closed"),
	"assigned":          setOf("in_progress", "false_positive", "risk_accepted", "remediated", "closed"),
	"in_progress":       setOf("remediated", "false_positive", "risk_accepted", "closed"),
	"risk_accepted":     setOf("open", "closed"),
	"false_positive":    setOf("open", "closed"),
	"remediated":        setOf("retest_requested", "closed", "open"),
	"retest_requested":  setOf("retest_passed", "retest_failed"),
	"retest_passed":     setOf("closed"),
	"retest_failed":     setOf("open"),
	"closed":            setOf("open"),
}

func setOf(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

// IngestInput is the canonical normalized form a parser produces.
type IngestInput struct {
	PlatformID       uuid.UUID
	PartnerID        uuid.UUID
	TenantID         uuid.UUID
	EngagementID     uuid.UUID
	AssetID          *uuid.UUID
	ScanJobID        *uuid.UUID
	Title            string
	Description      string
	Severity         string
	Confidence       string
	CVSSScore        float64
	CVSSVector       string
	CWE              string
	CVE              string
	Scanner          string
	ScanType         string
	AffectedEndpoint string
	Port             int
	Protocol         string
	EvidenceSummary  string
	BusinessImpact   string
	TechnicalImpact  string
	Remediation      string
	References       []string
}

// Upsert applies the deduplication rules and either inserts a new finding or
// bumps last_seen on an existing one. Returns (finding, isNew).
func (s *Service) Upsert(ctx context.Context, in IngestInput) (*models.Finding, bool, error) {
	if in.Title == "" || in.Severity == "" || in.Scanner == "" {
		return nil, false, errors.New("findings: title, severity, scanner required")
	}
	in.Severity = strings.ToLower(in.Severity)
	if !validSeverity(in.Severity) {
		in.Severity = "info"
	}
	if in.Confidence == "" {
		in.Confidence = "medium"
	}
	// VS-07: apply tenant severity overrides BEFORE the canonical insert so
	// the persisted row carries the overridden severity (which means SLA
	// computation in the same tx uses the corrected value).
	overriddenFrom := ""
	if newSev, prev, err := s.ApplyOverrides(ctx, in.TenantID, in); err == nil && newSev != in.Severity {
		overriddenFrom = prev
		in.Severity = newSev
	}
	fp := dedupFingerprint(in)
	refs, _ := json.Marshal(in.References)
	id := uuid.New()
	now := time.Now().UTC()

	var (
		newID uuid.UUID
		isNew bool
	)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	// Single-statement upsert. xmax = 0 on the returned row means the INSERT
	// path won (no prior row); a non-zero xmax means the DO UPDATE fired.
	// This avoids the "transaction aborted by unique violation" problem
	// that splitting INSERT + UPDATE inside one tx would hit.
	err = tx.QueryRow(ctx, `
		INSERT INTO findings(id, platform_id, partner_id, tenant_id, engagement_id, asset_id,
		    scan_job_id, title, description, severity, confidence, cvss_score, cvss_vector,
		    cwe, cve, scanner, scan_type, affected_endpoint, port, protocol,
		    evidence_summary, business_impact, technical_impact, remediation, "references",
		    status, first_seen, last_seen, dedup_fingerprint)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
		        $21,$22,$23,$24,$25,'open',$26,$26,$27)
		ON CONFLICT (tenant_id, dedup_fingerprint) DO UPDATE
		   SET last_seen   = EXCLUDED.last_seen,
		       scan_job_id = COALESCE(EXCLUDED.scan_job_id, findings.scan_job_id)
		RETURNING id, (xmax = 0) AS is_new`,
		id, in.PlatformID, in.PartnerID, in.TenantID, in.EngagementID, in.AssetID,
		in.ScanJobID, in.Title, in.Description, in.Severity, in.Confidence, in.CVSSScore,
		in.CVSSVector, in.CWE, in.CVE, in.Scanner, in.ScanType, in.AffectedEndpoint,
		in.Port, in.Protocol, in.EvidenceSummary, in.BusinessImpact, in.TechnicalImpact,
		in.Remediation, refs, now, fp,
	).Scan(&newID, &isNew)
	if err != nil {
		return nil, false, fmt.Errorf("findings: upsert: %w", err)
	}
	if isNew {
		_, _ = tx.Exec(ctx, `
			INSERT INTO finding_status_history(finding_id, from_status, to_status, note)
			VALUES ($1, NULL, 'open', 'initial ingest')`, newID)
		// SLA: due_at = first_seen + tenant_settings.default_severity_sla[severity] days.
		// Falls back to 30 days when the tenant has no override.
		if _, err := tx.Exec(ctx, `
			UPDATE findings f SET due_at = f.first_seen +
			    make_interval(days => COALESCE(
			      ((SELECT default_severity_sla FROM tenant_settings WHERE tenant_id = f.tenant_id)
			          ->> f.severity)::int,
			      30))
			 WHERE f.id = $1`, newID); err != nil {
			return nil, false, fmt.Errorf("findings: compute due_at: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	if isNew {
		observability.FindingsIngested.WithLabelValues(in.Scanner, in.Severity).Inc()
	} else {
		observability.FindingsDeduplicated.Inc()
	}
	// VS-07: stamp the override audit trail + attach the similarity cluster
	// + evaluate suppression rules. Each one short-circuits cleanly on no-op.
	if isNew && overriddenFrom != "" {
		_, _ = s.pool.Exec(ctx,
			`UPDATE findings SET severity_overridden_from=$2 WHERE id=$1`,
			newID, overriddenFrom)
	}
	if isNew {
		if _, err := s.AttachCluster(ctx, newID, in); err != nil {
			return nil, false, fmt.Errorf("findings: attach cluster: %w", err)
		}
		if ruleID, reason, err := s.EvaluateSuppression(ctx, in.TenantID, in, in.AffectedEndpoint); err == nil && ruleID != uuid.Nil {
			_ = s.MarkSuppressed(ctx, newID, ruleID, reason)
		}
	}
	f, err := s.Get(ctx, newID)
	if err != nil {
		return nil, false, err
	}
	if isNew {
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.FindingNormalized, TenantID: &in.TenantID, PartnerID: &in.PartnerID,
			Payload: map[string]any{"finding_id": newID, "severity": in.Severity, "scanner": in.Scanner},
		})
	} else {
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.FindingDeduplicated, TenantID: &in.TenantID, PartnerID: &in.PartnerID,
			Payload: map[string]any{"finding_id": newID, "scanner": in.Scanner},
		})
	}
	return f, isNew, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Finding, error) {
	f := &models.Finding{}
	var refs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, partner_id, engagement_id, asset_id, scan_job_id,
		       title, COALESCE(description,''), severity, confidence,
		       COALESCE(cvss_score, 0), COALESCE(cvss_vector,''),
		       COALESCE(cwe,''), COALESCE(cve,''), scanner, scan_type,
		       COALESCE(affected_endpoint,''), COALESCE(port, 0), COALESCE(protocol,''),
		       COALESCE(evidence_summary,''), COALESCE(business_impact,''),
		       COALESCE(technical_impact,''), COALESCE(remediation,''), "references",
		       status, assigned_to, first_seen, last_seen, dedup_fingerprint
		  FROM findings WHERE id=$1`, id).
		Scan(&f.ID, &f.TenantID, &f.PartnerID, &f.EngagementID, &f.AssetID, &f.ScanJobID,
			&f.Title, &f.Description, &f.Severity, &f.Confidence, &f.CVSSScore, &f.CVSSVector,
			&f.CWE, &f.CVE, &f.Scanner, &f.ScanType, &f.AffectedEndpoint, &f.Port, &f.Protocol,
			&f.EvidenceSummary, &f.BusinessImpact, &f.TechnicalImpact, &f.Remediation, &refs,
			&f.Status, &f.AssignedTo, &f.FirstSeen, &f.LastSeen, &f.DedupFingerprint)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(refs, &f.References)
	return f, nil
}

type ListFilter struct {
	TenantID     uuid.UUID
	EngagementID *uuid.UUID
	Severity     []string
	Status       []string
	AssetID      *uuid.UUID
	Scanner      string
	Search       string
	Limit        int
	Offset       int
}

func (s *Service) List(ctx context.Context, f ListFilter) ([]models.Finding, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	args := []any{f.TenantID}
	q := `SELECT id, tenant_id, partner_id, engagement_id, asset_id, scan_job_id,
	             title, COALESCE(description,''), severity, confidence,
	             COALESCE(cvss_score, 0), COALESCE(cvss_vector,''),
	             COALESCE(cwe,''), COALESCE(cve,''), scanner, scan_type,
	             COALESCE(affected_endpoint,''), COALESCE(port, 0), COALESCE(protocol,''),
	             COALESCE(evidence_summary,''), COALESCE(business_impact,''),
	             COALESCE(technical_impact,''), COALESCE(remediation,''), "references",
	             status, assigned_to, first_seen, last_seen, dedup_fingerprint
	        FROM findings WHERE tenant_id=$1`
	if f.EngagementID != nil {
		q += fmt.Sprintf(" AND engagement_id=$%d", len(args)+1)
		args = append(args, *f.EngagementID)
	}
	if f.AssetID != nil {
		q += fmt.Sprintf(" AND asset_id=$%d", len(args)+1)
		args = append(args, *f.AssetID)
	}
	if len(f.Severity) > 0 {
		q += fmt.Sprintf(" AND severity = ANY($%d)", len(args)+1)
		args = append(args, f.Severity)
	}
	if len(f.Status) > 0 {
		q += fmt.Sprintf(" AND status = ANY($%d)", len(args)+1)
		args = append(args, f.Status)
	}
	if f.Scanner != "" {
		q += fmt.Sprintf(" AND scanner=$%d", len(args)+1)
		args = append(args, f.Scanner)
	}
	if f.Search != "" {
		q += fmt.Sprintf(" AND (title ILIKE $%d OR description ILIKE $%d)", len(args)+1, len(args)+1)
		args = append(args, "%"+f.Search+"%")
	}
	q += fmt.Sprintf(" ORDER BY last_seen DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Finding{}
	for rows.Next() {
		var fi models.Finding
		var refs []byte
		if err := rows.Scan(&fi.ID, &fi.TenantID, &fi.PartnerID, &fi.EngagementID, &fi.AssetID,
			&fi.ScanJobID, &fi.Title, &fi.Description, &fi.Severity, &fi.Confidence,
			&fi.CVSSScore, &fi.CVSSVector, &fi.CWE, &fi.CVE, &fi.Scanner, &fi.ScanType,
			&fi.AffectedEndpoint, &fi.Port, &fi.Protocol, &fi.EvidenceSummary,
			&fi.BusinessImpact, &fi.TechnicalImpact, &fi.Remediation, &refs,
			&fi.Status, &fi.AssignedTo, &fi.FirstSeen, &fi.LastSeen, &fi.DedupFingerprint); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refs, &fi.References)
		out = append(out, fi)
	}
	return out, rows.Err()
}

// Transition validates and applies a status change.
func (s *Service) Transition(ctx context.Context, actor *uuid.UUID, id uuid.UUID, to, note string) error {
	to = strings.ToLower(to)
	current, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	allowed, ok := AllowedTransitions[current.Status]
	if !ok || !allowed[to] {
		return fmt.Errorf("findings: invalid transition %s -> %s", current.Status, to)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE findings SET status=$2, updated_at=now() WHERE id=$1`, id, to); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_status_history(finding_id, from_status, to_status, changed_by, note)
		VALUES ($1,$2,$3,$4,$5)`, id, current.Status, to, actor, nullIfEmpty(note)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	event := audit.EventFindingEdited
	switch to {
	case "false_positive":
		event = audit.EventFindingFalsePositive
	case "risk_accepted":
		event = audit.EventFindingAccepted
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: current.PartnerID, PartnerID: &current.PartnerID, TenantID: &current.TenantID,
		ActorID: actor, Event: event,
		TargetType: "finding", TargetID: id.String(),
		Payload: map[string]any{"from": current.Status, "to": to, "note": note},
	})
	return nil
}

func (s *Service) Assign(ctx context.Context, actor *uuid.UUID, id, assignee uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE findings SET assigned_to=$2, status=CASE WHEN status='open' THEN 'assigned' ELSE status END,
		                     updated_at=now() WHERE id=$1`, id, assignee)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("findings: not found")
	}
	current, _ := s.Get(ctx, id)
	if current != nil {
		_ = s.bus.Publish(ctx, eventbus.Event{
			Type: eventbus.FindingAssigned, TenantID: &current.TenantID, PartnerID: &current.PartnerID,
			ActorID: actor, Payload: map[string]any{"finding_id": id, "assignee": assignee},
		})
	}
	return nil
}

// BulkPatch applies one of the supported bulk operations to the given
// finding IDs. Currently supported: status (any valid transition),
// assignee, and risk_accepted (sets status + records a justification).
type BulkPatchInput struct {
	TenantID    uuid.UUID
	IDs         []uuid.UUID
	Action      string     // status | assign | risk_accept
	Status      string     // for status
	AssigneeID  *uuid.UUID // for assign
	Note        string
	Actor       *uuid.UUID
}

func (s *Service) BulkPatch(ctx context.Context, in BulkPatchInput) (int, error) {
	if len(in.IDs) == 0 {
		return 0, nil
	}
	var changed int
	for _, id := range in.IDs {
		switch in.Action {
		case "status":
			if err := s.Transition(ctx, in.Actor, id, in.Status, in.Note); err == nil {
				changed++
			}
		case "assign":
			if in.AssigneeID == nil {
				return changed, errors.New("findings: bulk assign requires assignee_id")
			}
			if err := s.Assign(ctx, in.Actor, id, *in.AssigneeID); err == nil {
				changed++
			}
		case "risk_accept":
			if err := s.Transition(ctx, in.Actor, id, "risk_accepted", in.Note); err == nil {
				changed++
			}
		default:
			return 0, fmt.Errorf("findings: unknown bulk action %q", in.Action)
		}
	}
	return changed, nil
}

// AddComment appends a free-form comment to a finding. Comments thread off
// the finding detail page (Blueprint §33.2 "Comments" section).
type CommentInput struct {
	FindingID uuid.UUID
	AuthorID  *uuid.UUID
	Body      string
}

func (s *Service) AddComment(ctx context.Context, in CommentInput) (uuid.UUID, error) {
	if in.Body == "" {
		return uuid.Nil, errors.New("findings: comment body required")
	}
	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO finding_comments(id, finding_id, author_id, body)
		VALUES ($1, $2, $3, $4)`,
		id, in.FindingID, in.AuthorID, in.Body); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// Comment is one entry in a finding's comment thread.
type Comment struct {
	ID        uuid.UUID  `json:"id"`
	FindingID uuid.UUID  `json:"finding_id"`
	AuthorID  *uuid.UUID `json:"author_id,omitempty"`
	Body      string     `json:"body"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s *Service) ListComments(ctx context.Context, findingID uuid.UUID) ([]Comment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, finding_id, author_id, body, created_at
		  FROM finding_comments WHERE finding_id=$1 ORDER BY created_at`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Comment{}
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.FindingID, &c.AuthorID, &c.Body, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SweepSLABreaches stamps sla_breached_at on findings that have passed
// their due_at without being remediated. Returns the number freshly marked.
// Intended to be called by a periodic worker (e.g. every minute) or on
// demand by the audit page.
func (s *Service) SweepSLABreaches(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE findings
		   SET sla_breached_at = now()
		 WHERE due_at IS NOT NULL
		   AND due_at < now()
		   AND sla_breached_at IS NULL
		   AND status NOT IN ('closed','remediated','retest_passed','false_positive','risk_accepted')`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func dedupFingerprint(in IngestInput) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d|%s|%s|%s",
		strings.ToLower(in.Title), in.Scanner, in.AffectedEndpoint,
		in.CVE, in.CWE, in.Port, in.Protocol,
		strings.ToLower(in.Severity),
		hashAsset(in.AssetID))
	return hex.EncodeToString(h.Sum(nil))
}

func hashAsset(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func validSeverity(s string) bool {
	for _, v := range models.SeverityLevels {
		if v == s {
			return true
		}
	}
	return false
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var _ = pgx.ErrNoRows
