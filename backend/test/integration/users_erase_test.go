//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/users"
)

// TestUsers_EraseSweepsAllPIITables exercises the GDPR Art-17
// erasure path end-to-end against a live Postgres.
//
// Asserts:
//   * users row is pseudonymised (email/full_name redacted, status=erased)
//   * login_events rows for this user get their email nulled
//   * token_revocations rows have their `reason` cleared
//   * audit_logs gets a 'user.erased' row carrying the row counts
//   * the user can NOT be re-authenticated (status='erased' is final)
func TestUsers_EraseSweepsAllPIITables(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// 1. Seed a user with PII + activity.
	uid := uuid.New()
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO users(id, platform_id, partner_id, email, full_name,
		    mfa_enabled, status)
		VALUES ($1, $2, $3, $4, 'Erase Test User', false, 'active')`,
		uid, platformID, directID, fmt.Sprintf("erase-%s@vaultscan.test", uid.String()[:8])); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Seed login_events with the real email.
	for i := 0; i < 3; i++ {
		if _, err := h.pool.Exec(ctx, `
			INSERT INTO login_events(user_id, email, success, ip, user_agent, mfa_used)
			VALUES ($1, $2, true, '10.0.0.1'::inet, 'integration-test', false)`,
			uid, fmt.Sprintf("erase-%s@vaultscan.test", uid.String()[:8])); err != nil {
			t.Fatalf("seed login_events: %v", err)
		}
	}

	// Seed token_revocations with a reason string.
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO token_revocations(user_id, min_iat, revoked_by, reason)
		VALUES ($1, now(), $2, 'user-supplied reason text — contains PII fragment')
		ON CONFLICT (user_id) DO UPDATE SET reason = EXCLUDED.reason`,
		uid, adminID); err != nil {
		t.Fatalf("seed token_revocations: %v", err)
	}

	// 2. Run erase.
	report, err := h.users.Erase(ctx, uid, &adminID, "GDPR Art 17 — integration test")
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}

	// 3. Assert report counts.
	if report.UserID != uid {
		t.Errorf("report.UserID mismatch")
	}
	if report.LoginEventsSwept != 3 {
		t.Errorf("LoginEventsSwept = %d, want 3", report.LoginEventsSwept)
	}
	if report.TokenRevocationsSwept != 1 {
		t.Errorf("TokenRevocationsSwept = %d, want 1", report.TokenRevocationsSwept)
	}
	if !report.AuditRowsRetained {
		t.Error("AuditRowsRetained must be true")
	}

	// 4. Assert users row pseudonymised.
	var email, fullName, status string
	if err := h.pool.QueryRow(ctx,
		`SELECT email::text, full_name, status FROM users WHERE id = $1`, uid).
		Scan(&email, &fullName, &status); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !strings.HasPrefix(email, "erased+") || !strings.HasSuffix(email, "@invalid.local") {
		t.Errorf("email not pseudonymised: %q", email)
	}
	if !strings.HasPrefix(fullName, "ERASED USER ") {
		t.Errorf("full_name not pseudonymised: %q", fullName)
	}
	if status != "erased" {
		t.Errorf("status = %q, want 'erased'", status)
	}

	// 5. Assert login_events email nulled.
	var unsweptEmails int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_events WHERE user_id = $1 AND email IS NOT NULL`,
		uid).Scan(&unsweptEmails); err != nil {
		t.Fatalf("count login_events: %v", err)
	}
	if unsweptEmails != 0 {
		t.Errorf("login_events.email not nulled — %d rows still have it", unsweptEmails)
	}

	// 6. Assert token_revocations.reason cleared.
	var reason *string
	if err := h.pool.QueryRow(ctx,
		`SELECT reason FROM token_revocations WHERE user_id = $1`, uid).
		Scan(&reason); err != nil {
		t.Fatalf("read token_revocations: %v", err)
	}
	if reason != nil && *reason != "" {
		t.Errorf("token_revocations.reason not cleared: %q", *reason)
	}

	// 7. Assert audit_logs got a user.erased row referencing the swept totals.
	var auditEvent, payload string
	if err := h.pool.QueryRow(ctx, `
		SELECT event, payload::text FROM audit_logs
		 WHERE target_id = $1::text AND event = 'user.erased'
		 ORDER BY id DESC LIMIT 1`, uid).
		Scan(&auditEvent, &payload); err != nil {
		t.Fatalf("read audit_logs: %v", err)
	}
	if auditEvent != "user.erased" {
		t.Errorf("event mismatch: %q", auditEvent)
	}
	for _, key := range []string{"login_events_swept", "token_revocations_swept", "regulation"} {
		if !strings.Contains(payload, key) {
			t.Errorf("audit payload missing key %q; payload = %s", key, payload)
		}
	}
}

// TestUsers_EraseIdempotent — running Erase twice on the same user
// must not crash; the second run reports zero swept rows.
func TestUsers_EraseIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	uid := uuid.New()
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO users(id, platform_id, partner_id, email, full_name, status)
		VALUES ($1, $2, $3, $4, 'Idempotent', 'active')`,
		uid, platformID, directID, fmt.Sprintf("idem-%s@vaultscan.test", uid.String()[:8])); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r1, err := h.users.Erase(ctx, uid, &adminID, "first")
	if err != nil {
		t.Fatalf("first erase: %v", err)
	}
	r2, err := h.users.Erase(ctx, uid, &adminID, "second")
	if err != nil {
		t.Fatalf("second erase: %v", err)
	}
	_ = r1
	// Second run sweeps zero login_events / token_revocations because
	// they were nulled / cleared on the first pass.
	if r2.LoginEventsSwept != 0 {
		t.Errorf("idempotent second run swept %d login_events, want 0", r2.LoginEventsSwept)
	}
}

// Mostly defensive: confirm that the users service is wired into the
// harness (build-time guard).
var _ = (*users.Service)(nil)
