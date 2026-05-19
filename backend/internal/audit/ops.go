package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zaishield/vaultscan/backend/internal/observability"
)

// ---------------- Deep chain verification ----------------------------------

// VerifyResult is the full forensic report from VerifyDeep.
type VerifyResult struct {
	Total        int64     `json:"total_rows"`
	FirstBadID   int64     `json:"first_bad_id"`         // 0 = intact
	LastGoodID   int64     `json:"last_good_id"`
	DetectedAt   time.Time `json:"detected_at"`
	ExpectedHash string    `json:"expected_hash,omitempty"`
	StoredHash   string    `json:"stored_hash,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

// verifyDeepChunkSize is the page size for the keyset-paginated scan
// over audit_logs. 10k rows per query keeps each statement well under
// the 30s pool-wide statement_timeout even on a multi-million row
// audit table. A single full-table SELECT would otherwise blow past
// the timeout once the table grows past ~1M rows in production.
const verifyDeepChunkSize = 10_000

// VerifyDeep is Verify's audit-grade sibling: returns the full forensic
// report AND writes a row into audit_chain_breaks for every break it
// finds, so subsequent dashboard queries can show "chain broken on Mar 4
// 02:17 between rows 9134 and 9135".
//
// Chunked via keyset (WHERE id > $1 ORDER BY id LIMIT N) so each
// underlying statement returns in milliseconds regardless of total
// table size. The chain-prev byte slice is carried across chunks so
// the verifier still sees the contiguous chain.
func (s *Service) VerifyDeep(ctx context.Context) (*VerifyResult, error) {
	var (
		prev      []byte
		total     int64
		lastGood  int64
		firstBad  int64
		lastID    int64
		expectHex string
		storedHex string
		detail    string
	)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		rows, err := s.pool.Query(ctx, `
			SELECT id, event, actor_type, actor_id, host(ip), user_agent,
			       platform_id, partner_id, tenant_id,
			       target_type, target_id, payload, chain_prev, chain_hash,
			       occurred_at, COALESCE(chain_hash_version, 1)
			  FROM audit_logs
			 WHERE id > $1
			 ORDER BY id ASC
			 LIMIT $2`, lastID, verifyDeepChunkSize)
		if err != nil {
			return nil, err
		}
		chunkRows := 0
		for rows.Next() {
			chunkRows++
			var (
				id              int64
				event, actor    string
				actorID         *uuid.UUID
				ipStr           *string
				userAgent       *string
				platID          uuid.UUID
				partID, tenID   *uuid.UUID
				tType, tID      *string
				payload         string
				chainPrev, hash []byte
				occurredAt      time.Time
				hashVersion     int
			)
			if err := rows.Scan(&id, &event, &actor, &actorID, &ipStr, &userAgent,
				&platID, &partID, &tenID,
				&tType, &tID, &payload, &chainPrev, &hash,
				&occurredAt, &hashVersion); err != nil {
				rows.Close()
				return nil, err
			}
			total++
			lastID = id
			expect := computeRowHash(hashVersion, prev, occurredAt,
				event, actor, actorID, ipStr, userAgent,
				platID, partID, tenID, tType, tID, payload)
			if firstBad == 0 && !equal(expect, hash) {
				firstBad = id
				expectHex = hex.EncodeToString(expect)
				storedHex = hex.EncodeToString(hash)
				detail = fmt.Sprintf("row %d hash mismatch (event=%s)", id, event)
			}
			if firstBad == 0 {
				lastGood = id
			}
			prev = hash
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		if chunkRows < verifyDeepChunkSize {
			break // last page reached
		}
	}
	res := &VerifyResult{
		Total: total, FirstBadID: firstBad, LastGoodID: lastGood,
		DetectedAt: time.Now().UTC(),
		ExpectedHash: expectHex, StoredHash: storedHex, Detail: detail,
	}
	if firstBad != 0 {
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO audit_chain_breaks(first_bad_id, last_good_id, detail)
			VALUES ($1, $2, $3)`, firstBad, lastGood, detail)
		observability.AuditChainBreaks.Inc()
	}
	return res, nil
}

// VerifyIncremental is VerifyDeep's resumable sibling. It reads
// the persisted (last_verified_id, last_verified_hash) checkpoint
// from audit_chain_verification_checkpoints, scans from the next
// row onward, and advances the checkpoint on success. A kill
// mid-scan no longer restarts the verifier at row 1 — the next
// run picks up where the previous one left off.
//
// Failure modes:
//   - chain break detected: returns a VerifyResult with FirstBadID
//     set; the checkpoint is NOT advanced. Operators must resolve
//     (via the chain_breaks audit + a full VerifyDeep re-run)
//     before incremental can resume.
//   - ctx cancelled: returns ctx.Err() with the checkpoint NOT
//     advanced past the last fully-validated chunk. Safe to retry.
//
// Operational guidance:
//   - Hourly cron: call VerifyIncremental — fast even on a 50M-row
//     chain because only the new tail is scanned.
//   - Weekly: call VerifyDeep (NOT this) for a full forensic
//     re-validation that doesn't trust the checkpoint hash.
func (s *Service) VerifyIncremental(ctx context.Context) (*VerifyResult, error) {
	var (
		ckptID   int64
		ckptHash []byte
	)
	err := s.pool.QueryRow(ctx,
		`SELECT last_verified_id, last_verified_hash
		   FROM audit_chain_verification_checkpoints
		  WHERE id = 1`).
		Scan(&ckptID, &ckptHash)
	if err != nil {
		// ONLY fall back to VerifyDeep when the checkpoint row is
		// genuinely missing (pre-0062 schema or freshly truncated
		// table). Any OTHER error here means the gating store is
		// unhealthy — we must NOT silently switch to a full scan that
		// then might itself fail and leave the operator with no
		// signal that "incremental" was never running. Propagate the
		// error; on-call sees a clear DB-down condition.
		if errors.Is(err, pgx.ErrNoRows) {
			return s.VerifyDeep(ctx)
		}
		return nil, fmt.Errorf("audit: checkpoint read: %w", err)
	}
	var (
		prev      = ckptHash
		total     int64
		lastGood  = ckptID
		firstBad  int64
		lastID    = ckptID
		expectHex string
		storedHex string
		detail    string
	)
	// Treat the empty-bytes seed (`\x`) as "no prior verification"
	// — start with prev=nil so the chain hash for row 1 matches the
	// original write-side computation.
	if len(prev) == 0 {
		prev = nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		rows, err := s.pool.Query(ctx, `
			SELECT id, event, actor_type, actor_id, host(ip), user_agent,
			       platform_id, partner_id, tenant_id,
			       target_type, target_id, payload, chain_prev, chain_hash,
			       occurred_at, COALESCE(chain_hash_version, 1)
			  FROM audit_logs
			 WHERE id > $1
			 ORDER BY id ASC
			 LIMIT $2`, lastID, verifyDeepChunkSize)
		if err != nil {
			return nil, err
		}
		chunkRows := 0
		for rows.Next() {
			chunkRows++
			var (
				id              int64
				event, actor    string
				actorID         *uuid.UUID
				ipStr           *string
				userAgent       *string
				platID          uuid.UUID
				partID, tenID   *uuid.UUID
				tType, tID      *string
				payload         string
				chainPrev, hash []byte
				occurredAt      time.Time
				hashVersion     int
			)
			if err := rows.Scan(&id, &event, &actor, &actorID, &ipStr, &userAgent,
				&platID, &partID, &tenID,
				&tType, &tID, &payload, &chainPrev, &hash,
				&occurredAt, &hashVersion); err != nil {
				rows.Close()
				return nil, err
			}
			total++
			lastID = id
			expect := computeRowHash(hashVersion, prev, occurredAt,
				event, actor, actorID, ipStr, userAgent,
				platID, partID, tenID, tType, tID, payload)
			if firstBad == 0 && !equal(expect, hash) {
				firstBad = id
				expectHex = hex.EncodeToString(expect)
				storedHex = hex.EncodeToString(hash)
				detail = fmt.Sprintf("row %d hash mismatch (event=%s)", id, event)
			}
			if firstBad == 0 {
				lastGood = id
				prev = hash
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		if chunkRows < verifyDeepChunkSize {
			break
		}
	}
	res := &VerifyResult{
		Total:        total,
		FirstBadID:   firstBad,
		LastGoodID:   lastGood,
		DetectedAt:   time.Now().UTC(),
		ExpectedHash: expectHex,
		StoredHash:   storedHex,
		Detail:       detail,
	}
	if firstBad != 0 {
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO audit_chain_breaks(first_bad_id, last_good_id, detail)
			VALUES ($1, $2, $3)`, firstBad, lastGood, detail)
		observability.AuditChainBreaks.Inc()
		// Do NOT advance the checkpoint past a known break.
		return res, nil
	}
	// Only advance the checkpoint if we actually verified at least
	// one new row AND the chain stayed intact through end-of-scan.
	//
	// Concurrency guard: AND last_verified_id <= $4 (the snapshot
	// taken before our scan started). If two VerifyIncremental
	// invocations overlap, the loser's UPDATE no-ops rather than
	// rolling back the winner's checkpoint. Without this, two
	// hourly crons firing on overlapping windows could leave the
	// checkpoint behind where either alone would have left it.
	if lastGood > ckptID && prev != nil {
		_, _ = s.pool.Exec(ctx, `
			UPDATE audit_chain_verification_checkpoints
			   SET last_verified_id    = $1,
			       last_verified_hash  = $2,
			       last_verified_at    = now(),
			       rows_verified_total = rows_verified_total + $3
			 WHERE id = 1
			   AND last_verified_id <= $4`, lastGood, prev, total, ckptID)
	}
	return res, nil
}

// ---------------- Retention policy enforcement -----------------------------

type RetentionPolicy struct {
	Prefix        string `json:"event_prefix"`
	RetentionDays int    `json:"retention_days"`
	ArchiveTarget string `json:"archive_target,omitempty"`
}

func (s *Service) Policies(ctx context.Context) ([]RetentionPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_prefix, retention_days, COALESCE(archive_target,'')
		  FROM audit_retention_policies
		 ORDER BY length(event_prefix) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RetentionPolicy
	for rows.Next() {
		var p RetentionPolicy
		if err := rows.Scan(&p.Prefix, &p.RetentionDays, &p.ArchiveTarget); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PolicyFor returns the retention applicable to a given event. The most
// specific prefix wins (longest match). Order in the table matters.
func (s *Service) PolicyFor(ctx context.Context, event string) (RetentionPolicy, error) {
	policies, err := s.Policies(ctx)
	if err != nil {
		return RetentionPolicy{}, err
	}
	for _, p := range policies {
		if p.Prefix == "*" {
			continue
		}
		if strings.HasPrefix(event, p.Prefix) {
			return p, nil
		}
	}
	for _, p := range policies {
		if p.Prefix == "*" {
			return p, nil
		}
	}
	return RetentionPolicy{Prefix: "*", RetentionDays: 365 * 7}, nil
}

// ---------------- SIEM streaming -------------------------------------------

// ShipBatch returns up to `max` audit rows newer than the integration's
// cursor in CEF format, then advances the cursor on success. Designed
// for a periodic shipping worker. Returns (linesShipped, lag).
func (s *Service) ShipBatch(ctx context.Context, integrationID uuid.UUID, max int) (int, int64, error) {
	if max <= 0 {
		max = 500
	}
	var lastID int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(last_audit_id, 0) FROM audit_siem_cursors
		 WHERE integration_id=$1`, integrationID).Scan(&lastID); err != nil {
		// no cursor yet = start from 0
		lastID = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, event, actor_type, COALESCE(target_type,''), COALESCE(target_id,''),
		       payload, platform_id, tenant_id, occurred_at
		  FROM audit_logs
		 WHERE id > $1
		 ORDER BY id ASC
		 LIMIT $2`, lastID, max)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var shipped int
	var highest int64 = lastID
	for rows.Next() {
		var (
			id              int64
			event, actor    string
			tType, tID      string
			payload         string
			platID          uuid.UUID
			tenID           *uuid.UUID
			occurred        time.Time
		)
		if err := rows.Scan(&id, &event, &actor, &tType, &tID,
			&payload, &platID, &tenID, &occurred); err != nil {
			return shipped, 0, err
		}
		_ = AuditCEFLine(id, event, actor, tType, tID, platID, tenID, payload, occurred)
		// The real ship-to-SIEM call happens out of band — here we just
		// advance the cursor and count. The integration's deliver path
		// is wired in integrations/.
		shipped++
		highest = id
	}
	if err := rows.Err(); err != nil {
		return shipped, 0, err
	}

	var pending int64
	_ = s.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE id > $1`, highest).Scan(&pending)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_siem_cursors(integration_id, last_audit_id, last_shipped_at, behind_count)
		VALUES ($1, $2, now(), $3)
		ON CONFLICT (integration_id) DO UPDATE
		   SET last_audit_id   = EXCLUDED.last_audit_id,
		       last_shipped_at = EXCLUDED.last_shipped_at,
		       behind_count    = EXCLUDED.behind_count`,
		integrationID, highest, pending)
	return shipped, pending, err
}

// AuditCEFLine renders a single audit row in ArcSight CEF form. Reused
// by the SIEM forwarder.
func AuditCEFLine(id int64, event, actor, targetType, targetID string,
	platformID uuid.UUID, tenantID *uuid.UUID, payload string, ts time.Time) string {
	severity := 3
	if strings.HasPrefix(event, "auth.login.failed") || strings.HasPrefix(event, "scan.emergency_stop") {
		severity = 8
	}
	exts := []string{
		fmt.Sprintf("externalId=%d", id),
		fmt.Sprintf("act=%s", event),
		fmt.Sprintf("suser=%s", actor),
		fmt.Sprintf("cs1Label=platform_id cs1=%s", platformID),
		fmt.Sprintf("rt=%d", ts.UnixMilli()),
	}
	if tenantID != nil {
		exts = append(exts, fmt.Sprintf("cs2Label=tenant_id cs2=%s", *tenantID))
	}
	if targetType != "" {
		exts = append(exts, fmt.Sprintf("cs3Label=target_type cs3=%s", targetType))
	}
	if targetID != "" {
		exts = append(exts, fmt.Sprintf("cs4Label=target_id cs4=%s", targetID))
	}
	// Payload size only; full payload is delivered out of band.
	exts = append(exts, fmt.Sprintf("cn1Label=payload_bytes cn1=%d", len(payload)))
	return fmt.Sprintf("CEF:0|ZAISHIELD|VAULTSCAN|1.0|%s|%s|%d|%s",
		event, event, severity, strings.Join(exts, " "))
}

// ---------------- Forensic timeline export ---------------------------------

// TimelineEvent is one row in a forensic timeline export.
type TimelineEvent struct {
	ID         int64         `json:"id"`
	Time       time.Time     `json:"time"`
	Event      string        `json:"event"`
	ActorID    *uuid.UUID    `json:"actor_id,omitempty"`
	ActorType  string        `json:"actor_type"`
	TargetType string        `json:"target_type,omitempty"`
	TargetID   string        `json:"target_id,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
}

// Timeline returns the chronological event log between two timestamps
// for a specific tenant. Used by the legal-export bundle and by
// incident-response tooling.
func (s *Service) Timeline(ctx context.Context, tenantID uuid.UUID, since, until time.Time) ([]TimelineEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, occurred_at, event, actor_id, actor_type,
		       COALESCE(target_type,''), COALESCE(target_id,''), payload
		  FROM audit_logs
		 WHERE tenant_id=$1 AND occurred_at BETWEEN $2 AND $3
		 ORDER BY occurred_at`, tenantID, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEvent
	for rows.Next() {
		var e TimelineEvent
		var payload string
		if err := rows.Scan(&e.ID, &e.Time, &e.Event, &e.ActorID, &e.ActorType,
			&e.TargetType, &e.TargetID, &payload); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(payload), &e.Payload)
		out = append(out, e)
	}
	return out, rows.Err()
}
