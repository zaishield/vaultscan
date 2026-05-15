//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/email"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
	"github.com/zaishield/vaultscan/backend/internal/users"
)

// TestUsers_CreateAssignAndLoginEvents covers VS-01 deepenings:
//   * Create a user
//   * Grant a tenant-scoped role
//   * RolesForUser returns it
//   * RecordLogin writes login_events + an audit_logs row with chain hash
func TestUsers_CreateAssignAndLoginEvents(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, _ := h.makeTenant(t, "users-ops")
	userSvc := users.New(h.pool, h.audit)

	u, err := userSvc.Create(ctx, users.CreateInput{
		PlatformID: platformID, PartnerID: &directID, TenantID: &tenantID,
		Email: "operator@globex.example", FullName: "Operator", MFAEnabled: true,
		Actor: &adminID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var roleID uuid.UUID
	if err := h.pool.QueryRow(ctx,
		`SELECT id FROM roles WHERE code='tenant_admin'`).Scan(&roleID); err != nil {
		t.Fatalf("look up role: %v", err)
	}
	if err := userSvc.AssignRole(ctx, users.AssignRoleInput{
		UserID: u.ID, RoleID: roleID, ScopeTenant: &tenantID, GrantedBy: &adminID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	codes, err := userSvc.RolesForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("roles: %v", err)
	}
	if len(codes) != 1 || codes[0] != "tenant_admin" {
		t.Fatalf("expected [tenant_admin], got %v", codes)
	}

	// Successful login.
	if err := userSvc.RecordLogin(ctx, users.LoginEvent{
		UserID: &u.ID, PlatformID: platformID, Email: u.Email,
		Success: true, MFAUsed: true,
		IP: net.ParseIP("198.51.100.5"), UserAgent: "integration-test",
	}); err != nil {
		t.Fatalf("record login: %v", err)
	}
	var success bool
	if err := h.pool.QueryRow(ctx,
		`SELECT success FROM login_events WHERE user_id=$1`, u.ID).Scan(&success); err != nil {
		t.Fatalf("query login_events: %v", err)
	}
	if !success {
		t.Fatalf("expected success login_event")
	}

	// Failed login (no user).
	if err := userSvc.RecordLogin(ctx, users.LoginEvent{
		PlatformID: platformID, Email: "nobody@globex.example", Success: false,
	}); err != nil {
		t.Fatalf("record failed login: %v", err)
	}
	var failedCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_events WHERE success=false`).Scan(&failedCount)
	if failedCount < 1 {
		t.Fatalf("expected failed login_event")
	}

	// Audit chain must still verify after the user lifecycle bursts above.
	brokenAt, err := h.audit.Verify(ctx)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if brokenAt != 0 {
		t.Fatalf("audit chain broken at id=%d after user ops", brokenAt)
	}
}

// TestEmail_TemplateRoundTrip covers VS-02 deepenings: per-partner template
// CRUD + rendering against {{ .var }} placeholders + the MemoryTransport
// trail.
func TestEmail_TemplateRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_ = h

	mem := &email.MemoryTransport{}
	svc := email.New(h.pool, mem)

	if err := svc.Upsert(ctx, directID, email.Template{
		Code:     "finding_assigned",
		Subject:  "[{{ .product_name }}] {{ .finding_severity }} finding assigned",
		BodyHTML: `<p>Hi {{ .recipient_name }} — finding {{ .finding_title }} assigned for engagement {{ .engagement_code }}.</p>`,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	msg, err := svc.SendTest(ctx, directID, "finding_assigned", "ops@globex.example")
	if err != nil {
		t.Fatalf("send-test: %v", err)
	}
	if msg.Subject == "" {
		t.Fatalf("empty subject after render")
	}
	if !contains(msg.BodyHTML, "Test alert") {
		t.Fatalf("body didn't substitute variables: %q", msg.BodyHTML)
	}
	if len(mem.Sent()) != 1 {
		t.Fatalf("transport must have collected the message")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > len(sub) && (containsAt(s, sub) >= 0)))
}
func containsAt(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestRoE_BlackoutBlocksScan covers VS-03 deepenings: a blackout window in
// rules_of_engagement makes Scope Guard return blocked_time_window even
// when the regular daily/weekly window allows.
func TestRoE_BlackoutBlocksScan(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "roe-blackout")
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"domain", "globex.example", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	// Configure rules-of-engagement with a blackout window covering "now".
	now := time.Now().UTC()
	if err := h.engagements.UpsertRoE(ctx, engagementID, engagements.RulesOfEngagement{
		EngagementID:    engagementID,
		MaxIntensity:    "standard",
		DaysOfWeek:      []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
		Blackouts: []engagements.Blackout{
			{
				Label:    "Black Friday Drill",
				StartsAt: now.Add(-time.Hour),
				EndsAt:   now.Add(time.Hour),
			},
		},
	}); err != nil {
		t.Fatalf("upsert RoE: %v", err)
	}

	d, err := h.scope.Evaluate(ctx, scopeguard.Inputs{
		TenantID: tenantID, PartnerID: directID, EngagementID: engagementID,
		ScanProfile: "external_standard_va", TargetType: "domain",
		TargetValue: "globex.example", Plane: "external", RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if d.Code != scopeguard.DecisionBlockedTimeWindow {
		t.Fatalf("expected blocked_time_window during blackout, got %s (%s)", d.Code, d.Reason)
	}
}

// TestIntegrations_HealthRollup: deliveries written manually flow through
// the health view with the right counts.
func TestIntegrations_HealthRollup(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Create a fresh integration row.
	id := uuid.New()
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO integrations(id, partner_id, type, name, enabled, config)
		VALUES ($1, $2, 'webhook', 'test-hook', true, '{"url":"http://example.invalid"}')`,
		id, directID); err != nil {
		t.Fatalf("insert integration: %v", err)
	}

	// Simulate three recent deliveries: 2 delivered, 1 failed.
	for i, status := range []string{"delivered", "delivered", "failed"} {
		if _, err := h.pool.Exec(ctx, `
			INSERT INTO integration_deliveries(integration_id, event_id, event_type, attempt, status)
			VALUES ($1, $2, 'TestEvent', $3, $4)`,
			id, uuid.New(), i+1, status); err != nil {
			t.Fatalf("insert delivery: %v", err)
		}
	}

	rows, err := h.pool.Query(ctx, `
		SELECT i.id, i.type, COUNT(*) FILTER (WHERE d.status='delivered'),
		       COUNT(*) FILTER (WHERE d.status='failed')
		  FROM integrations i
		  LEFT JOIN integration_deliveries d ON d.integration_id = i.id
		 WHERE i.id=$1 GROUP BY i.id`, id)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("no row returned")
	}
	var idOut uuid.UUID
	var typeOut string
	var delivered, failed int
	if err := rows.Scan(&idOut, &typeOut, &delivered, &failed); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if delivered != 2 || failed != 1 {
		t.Fatalf("expected 2 delivered / 1 failed, got %d/%d", delivered, failed)
	}

	// Audit shouldn't be broken by these inserts.
	if id, err := h.audit.Verify(ctx); err != nil || id != 0 {
		t.Fatalf("audit broken at %d (err=%v)", id, err)
	}
}

var _ = audit.EventUserCreated
