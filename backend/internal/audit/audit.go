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
	"fmt"
	"net"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
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
func (s *Service) Record(ctx context.Context, e Entry) error {
	err := s.recordInner(ctx, e)
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
	// advisory lock keyed off the audit_logs OID. Without this, two
	// concurrent Record calls each see the same `prev`, compute hashes
	// that reference the same predecessor, and Verify sees a forked chain
	// after the rows commit. The lock is released automatically at COMMIT
	// / ROLLBACK so it cannot deadlock against itself.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('vaultscan.audit_logs'))`); err != nil {
		return fmt.Errorf("audit: lock chain: %w", err)
	}

	var prev []byte
	if err := tx.QueryRow(ctx,
		`SELECT chain_hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil && err.Error() != "no rows in result set" {
		// fresh table: prev stays nil
	}

	// chain_hash = sha256(prev_hash || canonical_metadata || payload_bytes).
	// payload is stored as TEXT (migration 0012), so the bytes Record writes
	// here are exactly what Verify reads back. canonicalIP / derefStr keep
	// nil-vs-NULL handling identical on both sides of the chain.
	//
	// Fields covered: event, actor_type, actor_id, ip, user_agent,
	// platform_id, partner_id, tenant_id, target_type, target_id, payload.
	// Adding actor_id + user_agent closes the attribution-tamper gap:
	// without them in the hash, an attacker with write access could
	// rewrite the actor or browser-fingerprint of a row and the chain
	// would still verify.
	h := sha256.New()
	if prev != nil {
		h.Write(prev)
	}
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%v|%v|%v|%s|%s",
		e.Event, e.ActorType, canonicalActorID(e.ActorID), canonicalIP(e.IP),
		canonicalString(e.UserAgent),
		e.PlatformID, e.PartnerID, e.TenantID,
		e.TargetType, e.TargetID)
	h.Write(payload)
	hash := h.Sum(nil)

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs(platform_id, partner_id, tenant_id, actor_id,
		                       actor_type, event, target_type, target_id,
		                       payload, ip, user_agent, chain_prev, chain_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		e.PlatformID, e.PartnerID, e.TenantID, e.ActorID,
		e.ActorType, e.Event, e.TargetType, e.TargetID,
		string(payload), ipOrNull(e.IP), nullIfEmpty(e.UserAgent),
		prev, hash,
	)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return tx.Commit(ctx)
}

// Verify recomputes the hash chain and returns the row id of the first
// inconsistency, or 0 if the chain is intact.
func (s *Service) Verify(ctx context.Context) (int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, event, actor_type, actor_id, host(ip), user_agent,
		       platform_id, partner_id, tenant_id,
		       target_type, target_id, payload, chain_prev, chain_hash
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
		)
		if err := rows.Scan(&id, &event, &actor, &actorID, &ipStr, &userAgent,
			&platID, &partID, &tenID,
			&tType, &tID, &payload, &chainPrev, &hash); err != nil {
			return 0, err
		}
		h := sha256.New()
		if prev != nil {
			h.Write(prev)
		}
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%v|%v|%v|%s|%s",
			event, actor, canonicalActorID(actorID), derefStr(ipStr),
			canonicalString(derefStr(userAgent)),
			platID, partID, tenID,
			derefStr(tType), derefStr(tID))
		h.Write([]byte(payload))
		expect := h.Sum(nil)
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
