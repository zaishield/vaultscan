//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// TestVS12_DashboardLayouts: SaveLayout creates a row; saving another
// "default" layout for the same role flips the first one off.
func TestVS12_DashboardLayouts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs12-layout")
	svc := dashboards.New(h.pool)

	widgets := []dashboards.Widget{
		{ID: "a", Type: "counter", Title: "Critical", X: 0, Y: 0, W: 3, H: 2},
		{ID: "b", Type: "line", Title: "Scan trend", X: 3, Y: 0, W: 9, H: 2},
	}
	id1, err := svc.SaveLayout(ctx, adminID, &tenantID, "My Exec", "executive", widgets, true)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if id1 == uuid.Nil {
		t.Fatal("empty id")
	}

	// Save another default for same role: the new one wins.
	id2, err := svc.SaveLayout(ctx, adminID, &tenantID, "Risk View",
		"executive",
		[]dashboards.Widget{{ID: "x", Type: "table", Title: "Top findings", W: 12, H: 8}},
		true)
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id1 {
		t.Fatal("expected new layout id")
	}
	def, err := svc.DefaultLayout(ctx, adminID, "executive")
	if err != nil {
		t.Fatal(err)
	}
	if def.ID != id2 {
		t.Fatalf("expected default to be id2 (%s), got %s", id2, def.ID)
	}
	if !def.IsDefault {
		t.Fatal("default layout missing is_default flag")
	}

	all, err := svc.ListLayouts(ctx, adminID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 layouts, got %d", len(all))
	}
}

// TestVS12_GeoNodes: returns seeded coords for each region.
func TestVS12_GeoNodes(t *testing.T) {
	h := newHarness(t)
	svc := dashboards.New(h.pool)
	nodes, err := svc.GeoNodes(context.Background())
	if err != nil {
		t.Fatalf("geo: %v", err)
	}
	if len(nodes) < 5 {
		t.Fatalf("expected at least 5 seeded geo nodes, got %d", len(nodes))
	}
	// Region 'ae' should be Dubai.
	hit := false
	for _, n := range nodes {
		if n.Region == "ae" {
			hit = true
			if n.City != "Dubai" {
				t.Fatalf("ae region city expected Dubai, got %s", n.City)
			}
		}
	}
	if !hit {
		t.Fatalf("ae region missing from geo nodes")
	}
}

// TestVS12_ComplianceSnapshot: ingest findings matching PCI controls,
// confirm the snapshot counts non-zero at-risk controls.
func TestVS12_ComplianceSnapshot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, eng := h.makeTenant(t, "vs12-comp")
	svc := dashboards.New(h.pool)

	for _, in := range []findings.IngestInput{
		{Title: "TLS 1.0 enabled on tcp/443", Severity: "high", Scanner: "testssl"},
		{Title: "SQL injection in /login", Severity: "critical", Scanner: "zap"},
		{Title: "Open port 23 telnet detected", Severity: "high", Scanner: "nmap"},
	} {
		in.PlatformID = platformID
		in.PartnerID = directID
		in.TenantID = tenantID
		in.EngagementID = eng
		if _, _, err := h.findings.Upsert(ctx, in); err != nil {
			t.Fatal(err)
		}
	}

	snaps, err := svc.ComplianceForTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("snap: %v", err)
	}
	got := map[string]dashboards.ComplianceSnapshot{}
	for _, s := range snaps {
		got[s.Framework] = s
	}
	if pci, ok := got["pci_dss"]; !ok {
		t.Fatalf("pci_dss snapshot missing from %v", got)
	} else if pci.ControlsAtRisk == 0 {
		t.Fatalf("pci_dss should have at-risk controls given the findings: %+v", pci)
	} else if pci.BySeverity["critical"] < 1 {
		t.Fatalf("pci_dss by-severity missing critical: %+v", pci.BySeverity)
	}
}

// TestVS12_LiveStreamFanout: after subscribing, publishing a tenant-scoped
// event delivers to the subscriber's channel; an event for a different
// tenant does not.
func TestVS12_LiveStreamFanout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantA, _ := h.makeTenant(t, "vs12-stream-a")
	tenantB, _ := h.makeTenant(t, "vs12-stream-b")

	ls := dashboards.NewLiveStream(h.bus)

	ch, closer, err := ls.Subscribe(ctx, h.pool, adminID, tenantA, "executive")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer closer()

	// Publish an event for tenant A — expected to arrive.
	if err := h.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.FindingNormalized, TenantID: &tenantA,
		Payload: map[string]any{"severity": "high"},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-ch:
		if msg.Type != eventbus.FindingNormalized {
			t.Fatalf("unexpected event type %s", msg.Type)
		}
		if msg.Tenant != tenantA {
			t.Fatalf("expected tenant %s, got %s", tenantA, msg.Tenant)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected event on subscriber channel")
	}

	// Tenant B event must NOT arrive on tenant A's channel.
	if err := h.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.FindingNormalized, TenantID: &tenantB,
		Payload: map[string]any{"severity": "high"},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-ch:
		t.Fatalf("cross-tenant leak: tenant A subscriber got tenant B event: %+v", msg)
	case <-time.After(200 * time.Millisecond):
		// good — no event
	}

	// Subscription row exists.
	var count int
	_ = h.pool.QueryRow(ctx,
		`SELECT count(*) FROM dashboard_sse_subscriptions WHERE user_id=$1 AND closed_at IS NULL`,
		adminID).Scan(&count)
	if count != 1 {
		t.Fatalf("expected one active subscription row, got %d", count)
	}

	// ActiveCount reflects it.
	if ls.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount=1, got %d", ls.ActiveCount())
	}

	// Sanity: TenantA was set + channel labelled.
	_ = strings.Contains
}
