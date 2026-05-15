//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// TestHS02_VerifyDeepIntact: VerifyDeep on a healthy chain reports
// first_bad_id=0 and a sensible total count.
func TestHS02_VerifyDeepIntact(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.makeTenant(t, "hs02-deep")

	res, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Total == 0 {
		t.Fatal("expected at least one audit row from makeTenant")
	}
	if res.FirstBadID != 0 {
		t.Fatalf("expected intact chain, got first_bad_id=%d (%s)",
			res.FirstBadID, res.Detail)
	}
}

// TestHS02_TimelineRange: Timeline returns rows for the tenant within
// the window, ordered by occurred_at.
func TestHS02_TimelineRange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "hs02-timeline")

	since := time.Now().Add(-1 * time.Hour)
	until := time.Now().Add(1 * time.Hour)
	events, err := h.audit.Timeline(ctx, tenantID, since, until)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one timeline event")
	}
	// Confirm chronological order.
	for i := 1; i < len(events); i++ {
		if events[i].Time.Before(events[i-1].Time) {
			t.Fatalf("events out of order at i=%d", i)
		}
	}
}

// TestHS02_PolicyMatch: PolicyFor picks the longest matching prefix.
func TestHS02_PolicyMatch(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cases := []struct {
		event   string
		wantDays int
	}{
		{"auth.login.failed", 365 * 6},
		{"scan.created", 365 * 3},
		{"finding.edited", 365 * 10},
		{"tenant.created", 365 * 7},
	}
	for _, c := range cases {
		p, err := h.audit.PolicyFor(ctx, c.event)
		if err != nil {
			t.Fatalf("policy %s: %v", c.event, err)
		}
		if p.RetentionDays != c.wantDays {
			t.Fatalf("event %s expected %d days, got %d (prefix=%s)",
				c.event, c.wantDays, p.RetentionDays, p.Prefix)
		}
	}
}

// TestHS02_CEFAuditLine: renders an audit row to CEF with key fields.
func TestHS02_CEFAuditLine(t *testing.T) {
	tenantID := uuid.New()
	line := audit.AuditCEFLine(42, "auth.login.failed", "user", "session", "alice@example",
		uuid.MustParse("00000000-0000-0000-0000-0000000000a1"), &tenantID,
		`{"mfa_used":false}`, time.Now())
	for _, want := range []string{
		"CEF:0|ZAISHIELD|VAULTSCAN|1.0|auth.login.failed|auth.login.failed|8|",
		"externalId=42",
		"act=auth.login.failed",
		"cs1Label=platform_id",
		"cs2Label=tenant_id",
		"cs3Label=target_type",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("CEF missing %q in:\n%s", want, line)
		}
	}
}

// TestHS02_SIEMShipBatch: ShipBatch advances the cursor and reports lag.
func TestHS02_SIEMShipBatch(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.makeTenant(t, "hs02-siem")

	// Seed an integrations row (SIEM type, dummy URL).
	var integID uuid.UUID
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO integrations(type, name, enabled, config)
		VALUES ('siem', 'hs02-siem-test', true, '{"url":"https://localhost"}'::jsonb)
		RETURNING id`).Scan(&integID); err != nil {
		t.Fatal(err)
	}

	shipped, lag, err := h.audit.ShipBatch(ctx, integID, 100)
	if err != nil {
		t.Fatalf("ship: %v", err)
	}
	if shipped == 0 {
		t.Fatal("expected to ship at least one row from baseline audit traffic")
	}
	if lag < 0 {
		t.Fatalf("negative lag: %d", lag)
	}

	// Cursor is recorded.
	var cursor int64
	_ = h.pool.QueryRow(ctx,
		`SELECT last_audit_id FROM audit_siem_cursors WHERE integration_id=$1`,
		integID).Scan(&cursor)
	if cursor == 0 {
		t.Fatal("cursor not advanced")
	}

	// A second batch with no new rows ships 0.
	shipped2, _, _ := h.audit.ShipBatch(ctx, integID, 100)
	if shipped2 != 0 {
		t.Fatalf("expected 0 rows on second ship, got %d", shipped2)
	}
}
