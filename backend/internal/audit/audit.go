// Package audit provides hash-chained, append-only audit logging.
//
// Blueprint §32 requires immutable, tenant-scoped, exportable, SIEM-forwardable
// audit records. Each row hashes the prior row so any in-place modification is
// detectable.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/observability"
)

// auditLogger emits a structured warning whenever Record fails so that
// callers using `_ = svc.Record(...)` (the common pattern in handlers
// + services where audit failure must not block the primary tenant
// operation) still produce an ops-visible signal. Without this, a
// silently-failing audit pipeline would be detectable only by the
// chain-verify cron — and only via row absence.
var auditLogger = zerolog.New(os.Stderr).With().
	Timestamp().Str("component", "audit").Logger()

// Event types listed in Blueprint §32.1 (30+ entries) plus operational extras.
const (
	EventLoginSuccess          = "auth.login.success"
	EventLoginFailed           = "auth.login.failed"
	EventLogout                = "auth.logout"
	EventMFAChanged            = "auth.mfa.changed"
	EventUserCreated           = "user.created"
	EventRoleChanged           = "user.role.changed"
	EventPartnerCreated        = "partner.created"
	EventBrandingChanged       = "partner.branding.changed"
	EventTenantCreated         = "tenant.created"
	EventScopeAdded            = "scope.added"
	EventScopeApproved         = "scope.approved"
	EventAuthorizationUploaded = "authorization.uploaded"
	EventScanCreated           = "scan.created"
	EventScanApproved          = "scan.approved"
	EventScanStarted           = "scan.started"
	EventScanStopped           = "scan.stopped"
	EventScanCompleted         = "scan.completed"
	EventEmergencyStop         = "scan.emergency_stop"
	EventFindingEdited         = "finding.edited"
	EventFindingAccepted       = "finding.accepted"
	EventFindingFalsePositive  = "finding.false_positive"
	EventReportGenerated       = "report.generated"
	EventReportDownloaded      = "report.downloaded"
	EventEvidenceViewed        = "evidence.viewed"
	EventEvidenceDownloaded    = "evidence.downloaded"
	EventEvidenceUploaded      = "evidence.uploaded"
	EventAgentEnrolled         = "agent.enrolled"
	EventAgentDisconnected     = "agent.disconnected"
	EventAgentCertRotated      = "agent.cert.rotated"
	EventScopeGuardDecision    = "scopeguard.decision"
	EventIntegrationCreated    = "integration.created"
	EventRetestRequested       = "retest.requested"
	EventRetestPassed          = "retest.passed"
	EventRetestFailed          = "retest.failed"
)

type Service struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

type Entry struct {
	PlatformID uuid.UUID
	PartnerID  *uuid.UUID
	TenantID   *uuid.UUID
	ActorID    *uuid.UUID
	ActorType  string // user | service | agent | system
	Event      string
	TargetType string
	TargetID   string
	Payload    map[string]any
	IP         net.IP
	UserAgent  string
}

// Record appends a hash-chained entry. If anything fails, the call returns
// the error - callers should treat audit-failure as a hard error.
//
// Failure modes are also emitted as structured warning logs so callers
// using `_ = svc.Record(...)` still produce an ops-visible signal. The
// log carries event + actor + target so an operator can correlate the
// missing row with the in-flight tenant operation.
func (s *Service) Record(ctx context.Context, e Entry) (err error) {
	ctx, end := observability.Span(ctx, "audit.Record",
		"event", e.Event,
		"actor_type", e.ActorType,
		"target_type", e.TargetType)
	defer func() { end(err) }()
	err = s.recordInner(ctx, e)
	if err != nil {
		auditLogger.Warn().Err(err).
			Str("event", e.Event).
			Str("actor_type", e.ActorType).
			Str("target_type", e.TargetType).
			Str("target_id", e.TargetID).
			Msg("audit: record failed (chain row dropped)")
	}
	return err
}

func (s *Service) recordInner(ctx context.Context, e Entry) error {
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	if e.PlatformID == uuid.Nil {
		return fmt.Errorf("audit: platform_id required")
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("audit: marshal payload: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Serialise the read-prev + insert sequence with a transaction-scoped
	// advisory lock derived from a fixed lock-name. Without this, two
	// concurrent Record calls each see the same `prev`, compute hashes
	// that reference the same predecessor, and Verify sees a forked chain
	// after the rows commit. The lock is released automatically at COMMIT
	// / ROLLBACK so it cannot deadlock against itself.
	//
	// Lock-name derivation: hashtext('vaultscan.audit_logs'). This is
	// Postgres-specific (the hashtext function does not exist on other
	// engines). If the audit-log store is ever ported to MySQL / Spanner,
	// replace this with a hardcoded numeric lock id — the actual VALUE
	// doesn't matter as long as every Record call uses the same one.
	// hashtext gives a stable 32-bit hash of the string, which fits
	// cleanly in pg_advisory_xact_lock(int4).
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('vaultscan.audit_logs'))`); err != nil {
		return fmt.Errorf("audit: lock chain: %w", err)
	}

	var prev []byte
	if err := tx.QueryRow(ctx,
		`SELECT chain_hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil {
		// Fresh table: pgx.ErrNoRows is the only acceptable miss.
		// Anything else is a real DB error (column gone, conn drop,
		// permissions) — must abort, not silently restart the chain
		// from nil.
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("audit: read prev chain hash: %w", err)
		}
	}

	// chain_hash = sha256(prev_hash || canonical_metadata || payload_bytes).
	// payload is stored as TEXT (migration 0012), so the bytes Record writes
	// here are exactly what Verify reads back. canonicalIP / derefStr keep
	// nil-vs-NULL handling identical on both sides of the chain.
	//
	// v2 (migration 0067): includes occurred_at in the canonical
	// metadata so an attacker who can rewrite chain_prev/chain_hash
	// of a row can't ALSO float the timestamp without invalidating
	// the chain. We compute occurredAt explicitly here and pass it
	// to INSERT (instead of relying on DB DEFAULT now()) so the
	// timestamp the hash binds matches the timestamp persisted.
	//
	// Fields covered: occurred_at, event, actor_type, actor_id, ip,
	// user_agent, platform_id, partner_id, tenant_id, target_type,
	// target_id, payload.
	occurredAt := time.Now().UTC()
	const chainHashVersion = 2
	h := sha256.New()
	if prev != nil {
		h.Write(prev)
	}
	fmt.Fprintf(h, "v2|%s|%s|%s|%s|%s|%s|%v|%v|%v|%s|%s",
		occurredAt.Format(time.RFC3339Nano),
		e.Event, e.ActorType, canonicalActorID(e.ActorID), canonicalIP(e.IP),
		canonicalString(e.UserAgent),
		e.PlatformID, e.PartnerID, e.TenantID,
		e.TargetType, e.TargetID)
	h.Write(payload)
	hash := h.Sum(nil)

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs(platform_id, partner_id, tenant_id, actor_id,
		                       actor_type, event, target_type, target_id,
		                       payload, ip, user_agent, chain_prev, chain_hash,
		                       occurred_at, chain_hash_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		e.PlatformID, e.PartnerID, e.TenantID, e.ActorID,
		e.ActorType, e.Event, e.TargetType, e.TargetID,
		string(payload), ipOrNull(e.IP), nullIfEmpty(e.UserAgent),
		prev, hash, occurredAt, chainHashVersion,
	)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return tx.Commit(ctx)
}

// computeRowHash reconstructs the chain hash for a row, dispatching
// on hashVersion. v1 omits occurred_at; v2 includes it. Used by
// every Verify / VerifyDeep / VerifyIncremental code path so the
// algorithm-version dispatch lives in exactly one place.
func computeRowHash(
	hashVersion int,
	prev []byte,
	occurredAt time.Time,
	event, actor string,
	actorID *uuid.UUID, ipStr *string, userAgent *string,
	platID uuid.UUID, partID, tenID *uuid.UUID,
	tType, tID *string, payload string,
) []byte {
	h := sha256.New()
	if prev != nil {
		h.Write(prev)
	}
	switch hashVersion {
	case 2:
		fmt.Fprintf(h, "v2|%s|%s|%s|%s|%s|%s|%v|%v|%v|%s|%s",
			occurredAt.UTC().Format(time.RFC3339Nano),
			event, actor, canonicalActorID(actorID), derefStr(ipStr),
			canonicalString(derefStr(userAgent)),
			platID, partID, tenID,
			derefStr(tType), derefStr(tID))
	default: // v1
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%v|%v|%v|%s|%s",
			event, actor, canonicalActorID(actorID), derefStr(ipStr),
			canonicalString(derefStr(userAgent)),
			platID, partID, tenID,
			derefStr(tType), derefStr(tID))
	}
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// Verify recomputes the hash chain and returns the row id of the first
// inconsistency, or 0 if the chain is intact.
func (s *Service) Verify(ctx context.Context) (int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, event, actor_type, actor_id, host(ip), user_agent,
		       platform_id, partner_id, tenant_id,
		       target_type, target_id, payload, chain_prev, chain_hash,
		       occurred_at, COALESCE(chain_hash_version, 1)
		  FROM audit_logs ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var prev []byte
	for rows.Next() {
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
			return 0, err
		}
		expect := computeRowHash(hashVersion, prev, occurredAt,
			event, actor, actorID, ipStr, userAgent,
			platID, partID, tenID, tType, tID, payload)
		_ = canonicalIP // see Record() — derefStr handles the same canonical empty-string form.
		if !equal(expect, hash) {
			return id, nil
		}
		prev = hash
	}
	return 0, rows.Err()
}

func ipOrNull(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}

// VerifyTail revalidates only the last `tail` audit rows (default
// 256 when tail <= 0). Designed for the /readyz health check and
// per-request sampling — Verify() walks the whole chain (O(n) and
// can take minutes on a long-lived deployment), but VerifyTail
// gives an immediate "is the chain healthy right now?" answer with
// bounded cost.
//
// Returns the first inconsistent row id within the tail, or 0 if
// the tail is intact. Does NOT detect a tamper from before the
// tail — the hourly VerifyDeep cron is still the source of truth
// for full-history attestation.
func (s *Service) VerifyTail(ctx context.Context, tail int) (int64, error) {
	if tail <= 0 {
		tail = 256
	}
	// Pull the prev hash that anchors this tail so the rolling hash
	// state starts from the right place.
	var firstID int64
	if err := s.pool.QueryRow(ctx, `
		SELECT id FROM audit_logs ORDER BY id DESC OFFSET $1 - 1 LIMIT 1`,
		tail).Scan(&firstID); err != nil {
		// Fewer than `tail` rows in the table — full Verify is cheap.
		return s.Verify(ctx)
	}
	var anchor []byte
	if err := s.pool.QueryRow(ctx, `
		SELECT chain_prev FROM audit_logs WHERE id = $1`, firstID).Scan(&anchor); err != nil {
		return 0, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, event, actor_type, actor_id, host(ip), user_agent,
		       platform_id, partner_id, tenant_id,
		       target_type, target_id, payload, chain_prev, chain_hash,
		       occurred_at, COALESCE(chain_hash_version, 1)
		  FROM audit_logs WHERE id >= $1 ORDER BY id ASC`, firstID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := anchor
	for rows.Next() {
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
			return 0, err
		}
		want := computeRowHash(hashVersion, prev, occurredAt,
			event, actor, actorID, ipStr, userAgent,
			platID, partID, tenID, tType, tID, payload)
		if !equal(want, hash) {
			return id, nil
		}
		prev = hash
	}
	return 0, nil
}

// canonicalIP returns the form that Verify will read back. A nil net.IP is
// stored as SQL NULL, which Verify deserialises as the empty string.
func canonicalIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// canonicalActorID returns the form that hashes identically on
// Record + Verify. Both sides see *uuid.UUID; nil maps to the empty
// string sentinel (NOT "<nil>", to avoid colliding with %v's default
// nil rendering for other nullable columns).
func canonicalActorID(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// canonicalString collapses an empty-or-nil-equivalent string to "".
// Used for user_agent which can be NULL in the DB (no header sent) or
// empty (header sent with empty value). Both must hash the same.
func canonicalString(s string) string {
	return s
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
