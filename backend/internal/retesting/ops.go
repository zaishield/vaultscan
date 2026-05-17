package retesting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

// silence unused import warning when callers don't reach findings types via this file.
var _ = errors.New

// ----- Auto retest on remediation -----------------------------------------

// AutoLaunchIfEnabled checks the tenant's auto_retest_on_remediated flag
// and, if true, files a retest request for the finding. Designed to be
// called from a worker subscribed to the FindingRemediated bus event.
// Returns (retestID, launched, err); launched=false + nil error means the
// tenant has the flag off and we should silently skip.
func (s *Service) AutoLaunchIfEnabled(ctx context.Context, findingID uuid.UUID, actor *uuid.UUID) (uuid.UUID, bool, error) {
	f, err := s.findings.Get(ctx, findingID)
	if err != nil {
		return uuid.Nil, false, err
	}
	var enabled bool
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(auto_retest_on_remediated, false)
		   FROM tenant_settings WHERE tenant_id=$1`, f.TenantID).Scan(&enabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, err
	}
	if !enabled {
		return uuid.Nil, false, nil
	}

	// Don't re-file if one is already in-flight.
	var existing uuid.UUID
	_ = s.pool.QueryRow(ctx, `
		SELECT id FROM retest_requests
		 WHERE finding_id=$1 AND status IN ('pending','assigned','in_progress')
		 ORDER BY requested_at DESC LIMIT 1`, findingID).Scan(&existing)
	if existing != uuid.Nil {
		return existing, false, nil
	}

	id, err := s.Request(ctx, RequestInput{
		FindingID:   findingID,
		RequestedBy: actor,
		Note:        "auto-launched on remediation",
	})
	if err != nil {
		return uuid.Nil, false, err
	}
	// Capture the original-state snapshot so the diff has something to
	// compare against once the retest result lands.
	_ = s.captureOriginalSnapshot(ctx, id, findingID)
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: f.PlatformID, PartnerID: &f.PartnerID, TenantID: &f.TenantID,
		ActorID: actor, Event: "retest.auto_launched",
		TargetType: "retest_request", TargetID: id.String(),
		Payload: map[string]any{"finding_id": findingID},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.RetestRequested, TenantID: &f.TenantID, PartnerID: &f.PartnerID,
		ActorID: actor,
		Payload: map[string]any{"retest_id": id, "finding_id": findingID, "auto": true},
	})
	return id, true, nil
}

// SetAutoRetestEnabled is a small admin-side helper for tenant_settings.
func (s *Service) SetAutoRetestEnabled(ctx context.Context, tenantID uuid.UUID, on bool) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_settings(tenant_id, auto_retest_on_remediated)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE
		   SET auto_retest_on_remediated = EXCLUDED.auto_retest_on_remediated`,
		tenantID, on)
	return err
}

// ----- Bulk retest batches -------------------------------------------------

type Batch struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	RequestedBy    *uuid.UUID `json:"requested_by,omitempty"`
	Reason         string    `json:"reason"`
	Status         string    `json:"status"`
	TotalItems     int       `json:"total_items"`
	CompletedItems int       `json:"completed_items"`
	FailedItems    int       `json:"failed_items"`
	CreatedAt      time.Time `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// CreateBatch enqueues retest requests for every finding in `findingIDs`.
// Returns the batch ID + the count of items actually queued (skips
// findings already with an in-flight retest).
func (s *Service) CreateBatch(ctx context.Context, tenantID uuid.UUID, actor *uuid.UUID, reason string, findingIDs []uuid.UUID) (uuid.UUID, int, error) {
	if reason == "" {
		return uuid.Nil, 0, errors.New("retesting: batch reason required")
	}
	if len(findingIDs) == 0 {
		return uuid.Nil, 0, errors.New("retesting: empty batch")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, 0, err
	}
	defer tx.Rollback(ctx)

	var batchID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO retest_batches(tenant_id, requested_by, reason, total_items, status)
		VALUES ($1, $2, $3, $4, 'open')
		RETURNING id`, tenantID, actor, reason, len(findingIDs)).Scan(&batchID); err != nil {
		return uuid.Nil, 0, err
	}

	queued := 0
	for i, fid := range findingIDs {
		// Skip if there's already an in-flight retest for this finding.
		var existing uuid.UUID
		_ = tx.QueryRow(ctx, `
			SELECT id FROM retest_requests
			 WHERE finding_id=$1 AND status IN ('pending','assigned','in_progress')
			 LIMIT 1`, fid).Scan(&existing)
		var retestID uuid.UUID
		if existing != uuid.Nil {
			retestID = existing
		} else {
			if err := tx.QueryRow(ctx, `
				INSERT INTO retest_requests(finding_id, requested_by, note, status)
				VALUES ($1, $2, $3, 'pending')
				RETURNING id`, fid, actor, "bulk-retest: "+reason).Scan(&retestID); err != nil {
				return uuid.Nil, 0, err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retest_batch_items(batch_id, retest_request_id, ordinal, state)
			VALUES ($1, $2, $3, 'queued')`, batchID, retestID, i); err != nil {
			return uuid.Nil, 0, err
		}
		queued++
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, 0, err
	}
	return batchID, queued, nil
}

// MarkBatchItem flips the per-item state and (on terminal states) bumps
// the batch counters. Closes the batch when everything's accounted for.
func (s *Service) MarkBatchItem(ctx context.Context, batchID, retestID uuid.UUID, state string) error {
	if state != "running" && state != "done" && state != "failed" {
		return errors.New("retesting: invalid batch item state")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE retest_batch_items SET state=$3
		 WHERE batch_id=$1 AND retest_request_id=$2`,
		batchID, retestID, state); err != nil {
		return err
	}
	switch state {
	case "done":
		if _, err := tx.Exec(ctx, `
			UPDATE retest_batches
			   SET completed_items = completed_items + 1,
			       status = CASE WHEN completed_items + failed_items + 1 >= total_items
			                     THEN 'completed' ELSE 'in_progress' END,
			       completed_at = CASE WHEN completed_items + failed_items + 1 >= total_items
			                           THEN now() ELSE completed_at END
			 WHERE id=$1`, batchID); err != nil {
			return err
		}
	case "failed":
		if _, err := tx.Exec(ctx, `
			UPDATE retest_batches
			   SET failed_items = failed_items + 1,
			       status = CASE WHEN completed_items + failed_items + 1 >= total_items
			                     THEN 'completed' ELSE 'in_progress' END,
			       completed_at = CASE WHEN completed_items + failed_items + 1 >= total_items
			                           THEN now() ELSE completed_at END
			 WHERE id=$1`, batchID); err != nil {
			return err
		}
	case "running":
		if _, err := tx.Exec(ctx,
			`UPDATE retest_batches SET status='in_progress' WHERE id=$1 AND status='open'`,
			batchID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) GetBatch(ctx context.Context, id uuid.UUID) (*Batch, error) {
	b := &Batch{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, requested_by, reason, status,
		       total_items, completed_items, failed_items, created_at, completed_at
		  FROM retest_batches WHERE id=$1`, id).
		Scan(&b.ID, &b.TenantID, &b.RequestedBy, &b.Reason, &b.Status,
			&b.TotalItems, &b.CompletedItems, &b.FailedItems, &b.CreatedAt, &b.CompletedAt)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ----- Diff (original vs retest) -------------------------------------------

type findingSnapshot struct {
	ID               uuid.UUID `json:"id"`
	Title            string    `json:"title"`
	Severity         string    `json:"severity"`
	CVE              string    `json:"cve,omitempty"`
	CVSSScore        float64   `json:"cvss_score,omitempty"`
	AffectedEndpoint string    `json:"affected_endpoint,omitempty"`
	Port             int       `json:"port,omitempty"`
	Protocol         string    `json:"protocol,omitempty"`
	Status           string    `json:"status"`
}

func snapshotOf(f *models.Finding) findingSnapshot {
	return findingSnapshot{
		ID: f.ID, Title: f.Title, Severity: f.Severity, CVE: f.CVE,
		CVSSScore: f.CVSSScore, AffectedEndpoint: f.AffectedEndpoint,
		Port: f.Port, Protocol: f.Protocol, Status: f.Status,
	}
}

// captureOriginalSnapshot records the finding's state at retest-request
// time so the diff has a baseline.
func (s *Service) captureOriginalSnapshot(ctx context.Context, retestID, findingID uuid.UUID) error {
	f, err := s.findings.Get(ctx, findingID)
	if err != nil {
		return err
	}
	snap, _ := json.Marshal(snapshotOf(f))
	_, err = s.pool.Exec(ctx, `
		INSERT INTO retest_diffs(retest_request_id, original_snapshot)
		VALUES ($1, $2::jsonb)
		ON CONFLICT (retest_request_id) DO UPDATE
		   SET original_snapshot = EXCLUDED.original_snapshot`,
		retestID, snap)
	return err
}

type DiffSummary struct {
	Verdict          string         `json:"verdict"`            // resolved | regressed | unchanged | severity_dropped | severity_raised
	SeverityFrom     string         `json:"severity_from,omitempty"`
	SeverityTo       string         `json:"severity_to,omitempty"`
	OriginalSnapshot findingSnapshot `json:"original"`
	PostSnapshot     *findingSnapshot `json:"post,omitempty"`
}

// ComputeDiff is invoked after RecordResult fires. It compares the
// captured original_snapshot against the current finding state and
// writes the structured diff. Returns the verdict so the caller can
// surface it on the result page.
func (s *Service) ComputeDiff(ctx context.Context, retestID uuid.UUID) (*DiffSummary, error) {
	var (
		findingID  uuid.UUID
		origRaw    []byte
		outcome    string
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT r.finding_id, COALESCE(d.original_snapshot::text, '{}'),
		       COALESCE((SELECT outcome FROM retest_results
		                  WHERE retest_request_id = r.id
		                  ORDER BY decided_at DESC LIMIT 1), '')
		  FROM retest_requests r
		  LEFT JOIN retest_diffs d ON d.retest_request_id = r.id
		 WHERE r.id=$1`, retestID).Scan(&findingID, &origRaw, &outcome); err != nil {
		return nil, fmt.Errorf("retesting: load diff inputs: %w", err)
	}
	var orig findingSnapshot
	_ = json.Unmarshal(origRaw, &orig)
	f, err := s.findings.Get(ctx, findingID)
	if err != nil {
		return nil, err
	}
	post := snapshotOf(f)
	postBytes, _ := json.Marshal(post)

	verdict := "unchanged"
	switch outcome {
	case "passed":
		verdict = "resolved"
	case "failed":
		verdict = "regressed"
	}
	if orig.Severity != "" && post.Severity != "" && orig.Severity != post.Severity {
		ranked := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
		if ranked[post.Severity] < ranked[orig.Severity] {
			if verdict == "regressed" || verdict == "unchanged" {
				verdict = "severity_dropped"
			}
		} else if ranked[post.Severity] > ranked[orig.Severity] {
			verdict = "severity_raised"
		}
	}
	diff := map[string]any{
		"verdict":       verdict,
		"severity_from": orig.Severity,
		"severity_to":   post.Severity,
		"status_from":   orig.Status,
		"status_to":     post.Status,
	}
	diffBytes, _ := json.Marshal(diff)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO retest_diffs(retest_request_id, original_snapshot, post_snapshot, diff, summary)
		VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5)
		ON CONFLICT (retest_request_id) DO UPDATE
		   SET post_snapshot = EXCLUDED.post_snapshot,
		       diff          = EXCLUDED.diff,
		       summary       = EXCLUDED.summary,
		       computed_at   = now()`,
		retestID,
		nullableJSON(origRaw),
		postBytes, diffBytes,
		diffVerdictText(verdict, orig, post)); err != nil {
		return nil, err
	}
	// Stamp the finding rollup so the list UI can show the latest outcome.
	_, _ = s.pool.Exec(ctx, `
		UPDATE findings SET last_retest_outcome=$2, last_retest_at=now()
		 WHERE id=$1`, findingID, outcome)
	return &DiffSummary{
		Verdict:          verdict,
		SeverityFrom:     orig.Severity,
		SeverityTo:       post.Severity,
		OriginalSnapshot: orig,
		PostSnapshot:     &post,
	}, nil
}

func nullableJSON(b []byte) any {
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}

func diffVerdictText(v string, orig, post findingSnapshot) string {
	switch v {
	case "resolved":
		return fmt.Sprintf("finding resolved (was %s, severity %s)", orig.Status, orig.Severity)
	case "regressed":
		return "retest still finds the issue"
	case "severity_dropped":
		return fmt.Sprintf("severity dropped %s → %s", orig.Severity, post.Severity)
	case "severity_raised":
		return fmt.Sprintf("severity raised %s → %s", orig.Severity, post.Severity)
	}
	return "no change observed"
}

// GetDiff returns the most recent diff for a retest request.
func (s *Service) GetDiff(ctx context.Context, retestID uuid.UUID) (*DiffSummary, error) {
	var origRaw, postRaw, diffRaw []byte
	var summary string
	err := s.pool.QueryRow(ctx, `
		SELECT original_snapshot::text, COALESCE(post_snapshot::text, '{}'),
		       diff::text, COALESCE(summary, '')
		  FROM retest_diffs WHERE retest_request_id=$1`, retestID).
		Scan(&origRaw, &postRaw, &diffRaw, &summary)
	if err != nil {
		return nil, err
	}
	out := &DiffSummary{}
	_ = json.Unmarshal(origRaw, &out.OriginalSnapshot)
	if !strings.HasPrefix(string(postRaw), "{}") {
		var p findingSnapshot
		if err := json.Unmarshal(postRaw, &p); err == nil {
			out.PostSnapshot = &p
		}
	}
	var diff map[string]any
	_ = json.Unmarshal(diffRaw, &diff)
	if v, ok := diff["verdict"].(string); ok {
		out.Verdict = v
	}
	if v, ok := diff["severity_from"].(string); ok {
		out.SeverityFrom = v
	}
	if v, ok := diff["severity_to"].(string); ok {
		out.SeverityTo = v
	}
	return out, nil
}
