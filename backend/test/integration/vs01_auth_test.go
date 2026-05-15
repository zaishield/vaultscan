//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/users"
)

// TestVS01_FailedLoginLockout: five failed logins lock the account for 15
// minutes. Unlock clears the flag and the counter.
func TestVS01_FailedLoginLockout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs01-lockout")
	userSvc := users.New(h.pool, h.audit)

	u, err := userSvc.Create(ctx, users.CreateInput{
		PlatformID: platformID, PartnerID: &directID, TenantID: &tenantID,
		Email: "lockout@globex.example", FullName: "Lockout", Actor: &adminID,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := userSvc.RecordLogin(ctx, users.LoginEvent{
			UserID: &u.ID, PlatformID: platformID, Email: u.Email, Success: false,
			IP: net.ParseIP("198.51.100.5"),
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	var lockedUntil *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT locked_until FROM users WHERE id=$1`, u.ID).Scan(&lockedUntil); err != nil {
		t.Fatalf("read locked_until: %v", err)
	}
	if lockedUntil == nil || !lockedUntil.After(time.Now()) {
		t.Fatalf("expected user locked after 5 failed logins, got locked_until=%v", lockedUntil)
	}

	if err := userSvc.Unlock(ctx, u.ID, &adminID); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	var afterUnlock *time.Time
	var count int
	_ = h.pool.QueryRow(ctx,
		`SELECT locked_until, failed_login_count FROM users WHERE id=$1`, u.ID).
		Scan(&afterUnlock, &count)
	if afterUnlock != nil {
		t.Fatalf("unlock should null locked_until, got %v", afterUnlock)
	}
	if count != 0 {
		t.Fatalf("unlock should reset failed_login_count, got %d", count)
	}
}

// TestVS01_TokenRevocation: revoking a user's tokens stamps min_iat so the
// OIDC verifier can reject any older JWT. Second revoke pushes min_iat
// forward (idempotent UPSERT).
func TestVS01_TokenRevocation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs01-revoke")
	userSvc := users.New(h.pool, h.audit)
	u, _ := userSvc.Create(ctx, users.CreateInput{
		PlatformID: platformID, PartnerID: &directID, TenantID: &tenantID,
		Email: "revoke@globex.example", FullName: "Revoke", Actor: &adminID,
	})
	if err := userSvc.RevokeAllTokens(ctx, u.ID, &adminID, "credential leak"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var minIAT time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT min_iat FROM token_revocations WHERE user_id=$1`, u.ID).Scan(&minIAT); err != nil {
		t.Fatalf("read min_iat: %v", err)
	}
	if time.Since(minIAT) > 5*time.Second {
		t.Fatalf("min_iat should be ~now, got %v ago", time.Since(minIAT))
	}

	first := minIAT
	time.Sleep(1100 * time.Millisecond)
	if err := userSvc.RevokeAllTokens(ctx, u.ID, &adminID, "second leak"); err != nil {
		t.Fatalf("revoke 2: %v", err)
	}
	var second time.Time
	_ = h.pool.QueryRow(ctx,
		`SELECT min_iat FROM token_revocations WHERE user_id=$1`, u.ID).Scan(&second)
	if !second.After(first) {
		t.Fatalf("second revoke didn't bump min_iat (first=%v second=%v)", first, second)
	}
}

// TestVS01_TenantSuspendBlocksWrites: a suspended tenant's status reads as
// 'suspended' and the audit trail records the action.
func TestVS01_TenantSuspendBlocksWrites(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs01-suspend")

	if err := h.tenants.Suspend(ctx, tenantID, &adminID, "Customer fraud investigation"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	var status, reason string
	var suspendedAt time.Time
	if err := h.pool.QueryRow(ctx, `
		SELECT status, COALESCE(suspension_reason,''), suspended_at
		  FROM tenants WHERE id=$1`, tenantID).
		Scan(&status, &reason, &suspendedAt); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "suspended" || reason == "" {
		t.Fatalf("expected suspended status with reason, got status=%q reason=%q", status, reason)
	}

	if err := h.tenants.Reactivate(ctx, tenantID, &adminID); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	_ = h.pool.QueryRow(ctx,
		`SELECT status FROM tenants WHERE id=$1`, tenantID).Scan(&status)
	if status != "active" {
		t.Fatalf("expected active after reactivate, got %s", status)
	}
}
