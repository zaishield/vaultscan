//go:build integration

// Live cross-region failover proof.
//
// Setup:
//   * Two scanner regions in scanner_node_registry: "primary" + "secondary".
//   * Mark every node in "primary" as offline (status='degraded'). This
//     simulates a full regional outage.
//   * Orchestrator.WithFailoverRegions("primary=secondary"). Submit a
//     scan job targeting region "primary".
//
// Expected:
//   * orch.Submit succeeds (didn't fail open or block)
//   * The job's region was rewritten to "secondary" (we have to look it
//     up via the secondary node's id since the orchestrator stores
//     `scanner_node_id`, not a `region` literal on the scan_job).
//   * A scanner_failover_attempts row was written with from='primary',
//     to='secondary'.
//
// This proves the multi-region failover described in
// docs/operations/multi-region-failover.md actually triggers end-to-end
// without manual intervention.

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

func TestMultiRegion_Failover_PrimaryDownRoutesToSecondary(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Seed two regional scanner nodes.
	primaryID := uuid.New()
	secondaryID := uuid.New()
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO scanner_node_registry(id, region, hostname, public_ip,
		    cpu_cores, memory_mb, capacity_jobs, status, reverse_dns, abuse_contact)
		VALUES ($1, 'failover-primary',   'p.test', '203.0.113.10', 4, 8192, 8, 'degraded',
		        'p.test', 'abuse@p'),
		       ($2, 'failover-secondary', 's.test', '203.0.113.20', 4, 8192, 8, 'online',
		        's.test', 'abuse@s')`,
		primaryID, secondaryID); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}

	tenantID, engID := h.makeTenant(t, "failover-"+uuid.NewString()[:6])
	scope, err := h.engagements.AddScope(ctx, &adminID, engID,
		"cidr", "203.0.113.0/24", "external", "failover test")
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	if err := h.engagements.ApproveScope(ctx, &adminID, scope.ID); err != nil {
		t.Fatalf("ApproveScope: %v", err)
	}
	if err := h.engagements.Activate(ctx, &adminID, engID); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// Configure the orchestrator to fail over primary → secondary.
	failover := scanorch.NewFailoverRegionsFromEnv("failover-primary=failover-secondary")
	orch := h.scanorch.WithFailoverRegions(failover)

	job, dec, err := orch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engID,
		ProfileCode: "external_standard_va",
		Plane:       "external",
		Region:      "failover-primary",
		Targets:     []string{"203.0.113.42"},
		RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if job == nil {
		t.Fatalf("orchestrator returned no job; scope decision: %+v", dec)
	}

	// The job's scanner_node_id should be the secondary, proving the
	// orchestrator walked the failover ladder.
	if job.ScannerNodeID == nil {
		t.Fatal("job has no scanner_node_id assigned")
	}
	if *job.ScannerNodeID != secondaryID {
		t.Errorf("job routed to %s, want secondary %s", *job.ScannerNodeID, secondaryID)
	}

	// A scanner_failover_attempts row must record the cross-region pick.
	var attempts int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM scanner_failover_attempts
		  WHERE from_region='failover-primary' AND to_region='failover-secondary'`).
		Scan(&attempts); err != nil {
		t.Fatalf("count failover attempts: %v", err)
	}
	if attempts == 0 {
		t.Errorf("expected at least one scanner_failover_attempts row, got 0")
	}
}

// TestMultiRegion_Failover_NoLadderConfiguredFails confirms that when
// no failover ladder is set, a region with no online nodes returns
// an error rather than silently picking any other region.
func TestMultiRegion_Failover_NoLadderConfiguredFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Single degraded node in the isolated region.
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO scanner_node_registry(id, region, hostname, public_ip,
		    cpu_cores, memory_mb, capacity_jobs, status, reverse_dns, abuse_contact)
		VALUES ($1, 'isolated-region', 'iso.test', '203.0.113.30', 4, 4096, 4, 'degraded',
		        'iso.test', 'abuse@iso')`, uuid.New()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	tenantID, engID := h.makeTenant(t, "iso-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engID,
		"cidr", "203.0.113.0/24", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engID)

	// Orchestrator with NO failover ladder for "isolated-region".
	failover := scanorch.NewFailoverRegionsFromEnv("eu=eu-fallback")
	orch := h.scanorch.WithFailoverRegions(failover)
	_, _, err := orch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engID,
		ProfileCode: "external_standard_va",
		Plane:       "external",
		Region:      "isolated-region",
		Targets:     []string{"203.0.113.50"},
		RequestedBy: &adminID,
	})
	if err == nil {
		t.Fatal("expected error when no node available + no failover; got nil")
	}
}
