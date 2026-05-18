//go:build integration

// plane_gaps_test.go — integration tests for the GA-batch
// external + internal plane endpoints (migration 0061):
//   tenants/{id}/sso  — SAML/OIDC self-serve
//   tenants/{id}/scim/tokens — SCIM token rotation
//   planrequests — customer upgrade ask + operator decide
//   impersonation — support break-glass with full audit
//   tenant lifecycle — quarantine + migrate
//   compliance rollup — per-tenant per-framework coverage

package integration

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/impersonation"
	"github.com/zaishield/vaultscan/backend/internal/planrequests"
	"github.com/zaishield/vaultscan/backend/internal/scimtokens"
	"github.com/zaishield/vaultscan/backend/internal/ssoconfig"
)

func netParse(s string) net.IP { return net.ParseIP(s) }

func TestSSOConfig_Lifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tID, _ := h.makeTenant(t, "sso-lifecycle")
	svc := ssoconfig.New(h.pool, h.audit)

	// Empty default.
	cfg, err := svc.Get(ctx, tID)
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if cfg.ProviderType != "none" {
		t.Errorf("default provider_type = %q, want 'none'", cfg.ProviderType)
	}

	// Invalid provider rejected.
	_, err = svc.Set(ctx, tID, ssoconfig.SetInput{ProviderType: "facebook"}, &adminID)
	if !errors.Is(err, ssoconfig.ErrInvalidProvider) {
		t.Errorf("expected ErrInvalidProvider, got %v", err)
	}

	// SAML without metadata rejected.
	_, err = svc.Set(ctx, tID, ssoconfig.SetInput{ProviderType: "saml"}, &adminID)
	if err == nil {
		t.Error("expected saml-without-metadata to fail")
	}

	// Valid SAML config.
	c, err := svc.Set(ctx, tID, ssoconfig.SetInput{
		ProviderType: "saml", Enabled: true,
		MetadataXML: `<EntityDescriptor entityID="urn:example:sp"/>`,
		ClaimMapping: map[string]string{"email": "mail", "name": "displayName", "roles": "memberOf"},
	}, &adminID)
	if err != nil {
		t.Fatalf("set saml: %v", err)
	}
	if c.ProviderType != "saml" || !c.Enabled {
		t.Errorf("post-set: provider=%s enabled=%v", c.ProviderType, c.Enabled)
	}
	if c.ClaimMapping["email"] != "mail" {
		t.Errorf("claim mapping not persisted: %v", c.ClaimMapping)
	}

	// Switch to OIDC.
	c, err = svc.Set(ctx, tID, ssoconfig.SetInput{
		ProviderType: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example/.well-known/openid-configuration",
		ClientID:     "client-abc",
		ClientSecret: "shhh-secret",
	}, &adminID)
	if err != nil {
		t.Fatalf("switch oidc: %v", err)
	}
	if !c.ClientSecretSet {
		t.Errorf("oidc client_secret should be set")
	}

	// Empty secret leaves previous untouched.
	c, err = svc.Set(ctx, tID, ssoconfig.SetInput{
		ProviderType: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example/.well-known/openid-configuration",
		ClientID:     "client-abc",
	}, &adminID)
	if err != nil {
		t.Fatalf("re-set without secret: %v", err)
	}
	if !c.ClientSecretSet {
		t.Errorf("client_secret should still be set after re-set with empty secret")
	}

	// "-" clears the secret.
	c, err = svc.Set(ctx, tID, ssoconfig.SetInput{
		ProviderType: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example/.well-known/openid-configuration",
		ClientID:     "client-abc",
		ClientSecret: "-",
	}, &adminID)
	if err != nil {
		t.Fatalf("clear secret: %v", err)
	}
	if c.ClientSecretSet {
		t.Errorf(`expected client_secret cleared after "-"`)
	}
}

func TestSCIMTokens_Lifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tID, _ := h.makeTenant(t, "scim-tokens")
	svc := scimtokens.New(h.pool, h.audit)

	// Create a token; plaintext is returned ONCE.
	res, err := svc.Create(ctx, tID, "okta-prod", 0, adminID)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(res.Plaintext, "vss_") {
		t.Errorf("token should start with vss_ prefix, got %q", res.Plaintext)
	}

	// Verify the plaintext authenticates.
	ip := netParse("203.0.113.42")
	tok, err := svc.Verify(ctx, tID, res.Plaintext, ip)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok == nil {
		t.Fatal("verify returned nil — plaintext should authenticate")
	}

	// Wrong token doesn't.
	tok, err = svc.Verify(ctx, tID, "vss_wrong", ip)
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if tok != nil {
		t.Error("wrong token should NOT authenticate")
	}

	// Duplicate label rejected.
	_, err = svc.Create(ctx, tID, "okta-prod", 0, adminID)
	if !errors.Is(err, scimtokens.ErrTokenLabelDuplicate) {
		t.Errorf("expected ErrTokenLabelDuplicate, got %v", err)
	}

	// Revoke + verify it no longer works.
	if err := svc.Revoke(ctx, tID, res.Token.ID, adminID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	tok, err = svc.Verify(ctx, tID, res.Plaintext, ip)
	if err != nil {
		t.Fatalf("verify revoked: %v", err)
	}
	if tok != nil {
		t.Error("revoked token should NOT authenticate")
	}

	// List returns the revoked token in metadata (with revoked_at set).
	list, err := svc.List(ctx, tID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("expected at least the revoked token in list")
	}
	if list[0].RevokedAt == nil {
		t.Error("listed token should have RevokedAt set")
	}
}

func TestPlanRequests_FullFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	svc := planrequests.New(h.pool, h.audit)

	// File a request.
	req, err := svc.File(ctx, directID, adminID, "team", "enterprise",
		"customer asked for HIPAA BAA")
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	if req.Status != "pending" {
		t.Errorf("status = %q, want pending", req.Status)
	}

	// Same-plan request rejected.
	_, err = svc.File(ctx, directID, adminID, "team", "team", "x")
	if err == nil {
		t.Error("same-plan request should fail")
	}

	// List shows it.
	list, err := svc.ListForPartner(ctx, directID, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) == 0 || list[0].ID != req.ID {
		t.Errorf("list did not surface filed request")
	}

	// Pending list (operator view) shows it.
	pending, err := svc.ListPending(ctx)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	found := false
	for _, r := range pending {
		if r.ID == req.ID {
			found = true
		}
	}
	if !found {
		t.Error("pending list should include the new request")
	}

	// Approve.
	r2, err := svc.Decide(ctx, req.ID, adminID, "approved", "approved per quote Q-2026-001")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if r2.Status != "approved" {
		t.Errorf("post-decide status = %q, want approved", r2.Status)
	}
	if r2.DecidedAt == nil {
		t.Error("DecidedAt should be set post-decide")
	}

	// Re-deciding a non-pending request is a no-op (returns unchanged).
	r3, err := svc.Decide(ctx, req.ID, adminID, "rejected", "x")
	if err != nil {
		t.Fatalf("re-decide: %v", err)
	}
	if r3.Status != "approved" {
		t.Errorf("re-decide should not flip status; got %q", r3.Status)
	}

	// History transition row.
	if err := svc.RecordTransition(ctx, directID, "team", "enterprise",
		adminID, &req.ID, "applied per approved request"); err != nil {
		t.Fatalf("record transition: %v", err)
	}
}

func TestImpersonation_FullFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Seed a target user under a tenant.
	tID, _ := h.makeTenant(t, "imp-target")
	targetID := uuid.New()
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO users(id, platform_id, partner_id, tenant_id, email, full_name, status)
		VALUES ($1, $2, $3, $4, 'target@example.com', 'Target User', 'active')`,
		targetID, platformID, directID, tID); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	svc := impersonation.New(h.pool, h.audit)

	// Cannot impersonate self.
	_, err := svc.Start(ctx, adminID, impersonation.StartInput{
		TargetUserID: adminID,
		TicketRef:    "ZD-123", Reason: "test",
	})
	if !errors.Is(err, impersonation.ErrSelfImpersonation) {
		t.Errorf("expected ErrSelfImpersonation, got %v", err)
	}

	// Ticket ref required.
	_, err = svc.Start(ctx, adminID, impersonation.StartInput{
		TargetUserID: targetID, Reason: "test",
	})
	if !errors.Is(err, impersonation.ErrTicketRequired) {
		t.Errorf("expected ErrTicketRequired, got %v", err)
	}

	// Happy path.
	sess, err := svc.Start(ctx, adminID, impersonation.StartInput{
		TargetUserID: targetID,
		TicketRef:    "ZD-1234",
		Reason:       "investigating customer-reported scan failure",
		Duration:     30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if sess.ExpiresAt.Before(time.Now()) || sess.ExpiresAt.After(time.Now().Add(time.Hour)) {
		t.Errorf("expires_at out of expected band: %v", sess.ExpiresAt)
	}
	if sess.TargetEmail != "target@example.com" {
		t.Errorf("target email mismatch: %q", sess.TargetEmail)
	}

	// Active list includes it.
	active, err := svc.Active(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	found := false
	for _, s := range active {
		if s.ID == sess.ID {
			found = true
		}
	}
	if !found {
		t.Error("started session should appear in Active()")
	}

	// Touch increments counter.
	if err := svc.Touch(ctx, sess.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}

	// End closes it.
	if err := svc.End(ctx, sess.ID, adminID); err != nil {
		t.Fatalf("end: %v", err)
	}
	// Re-ending is a no-op (not an error).
	if err := svc.End(ctx, sess.ID, adminID); err != nil {
		t.Errorf("re-end should be no-op, got %v", err)
	}
	// Touching after end fails.
	if err := svc.Touch(ctx, sess.ID); !errors.Is(err, impersonation.ErrSessionExpired) {
		t.Errorf("touch after end: expected ErrSessionExpired, got %v", err)
	}
	// Audit rows recorded (both dual-audit events).
	var auditCount int
	if err := h.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		 WHERE event IN ('support.impersonation_started',
		                 'user.impersonated_by_support',
		                 'support.impersonation_ended')
		   AND payload->>'session_id' = $1`, sess.ID.String()).Scan(&auditCount); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount < 3 {
		t.Errorf("expected ≥3 audit rows for session, got %d", auditCount)
	}
}

func TestTenantLifecycle_QuarantineAndMigrate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Two partners.
	p2 := uuid.New()
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO partners(id, platform_id, parent_id, type_id, name, slug, status)
		SELECT $1, $2, NULL, pt.id, 'Migrate-Target', 'migrate-target', 'active'
		  FROM partner_types pt WHERE pt.code='distributor'`,
		p2, platformID); err != nil {
		t.Fatalf("seed partner: %v", err)
	}

	tID, _ := h.makeTenant(t, "lifecycle")

	// Migrate to p2.
	if err := h.tenants.MigrateToPartner(ctx, tID, p2, adminID, "MSSP swap test"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var currentPartner uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT partner_id FROM tenants WHERE id=$1`, tID).
		Scan(&currentPartner); err != nil {
		t.Fatalf("read post-migrate: %v", err)
	}
	if currentPartner != p2 {
		t.Errorf("partner_id = %v, want %v", currentPartner, p2)
	}

	// Migration history row.
	var histCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tenant_partner_migrations WHERE tenant_id=$1`, tID).
		Scan(&histCount); err != nil {
		t.Fatalf("history: %v", err)
	}
	if histCount != 1 {
		t.Errorf("migration history rows = %d, want 1", histCount)
	}

	// Quarantine for deletion.
	if err := h.tenants.QuarantineForDeletion(ctx, tID, &adminID, "decommission test"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	var status, qReason *string
	if err := h.pool.QueryRow(ctx,
		`SELECT status, quarantine_reason FROM tenants WHERE id=$1`, tID).
		Scan(&status, &qReason); err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if status == nil || *status != "suspended" {
		t.Errorf("post-quarantine status = %v, want suspended", status)
	}
	if qReason == nil || *qReason != "decommission test" {
		t.Errorf("quarantine_reason mismatch")
	}

	// Re-quarantine is rejected.
	if err := h.tenants.QuarantineForDeletion(ctx, tID, &adminID, "x"); err == nil {
		t.Error("re-quarantine should fail")
	}

	// Cancel restores.
	if err := h.tenants.CancelQuarantine(ctx, tID, &adminID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`SELECT status FROM tenants WHERE id=$1`, tID).Scan(&status); err != nil {
		t.Fatalf("read post-cancel: %v", err)
	}
	if status == nil || *status != "active" {
		t.Errorf("post-cancel status = %v, want active", status)
	}
}
