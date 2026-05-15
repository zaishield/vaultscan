//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/agents"
)

// TestAgent_EnrollHeartbeat covers the §13.4 enrollment flow + heartbeat
// status update against a live database.
func TestAgent_EnrollHeartbeat(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := adminID

	tenantID, _ := h.makeTenant(t, "agent-enroll")

	agent, token, err := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "globex-dc01", Location: "globex hq", FormFactor: "linux_vm",
		CreatedBy: &actor,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if agent.Status != "pending" {
		t.Fatalf("expected pending status, got %s", agent.Status)
	}
	if token == "" {
		t.Fatalf("empty enrollment token")
	}

	// Wrong token must be rejected.
	if err := h.agents.Enroll(ctx, agent.ID, "wrong-token", "PEM", "deadbeef"); err == nil {
		t.Fatalf("expected wrong token to fail")
	}

	// Correct token enrolls.
	if err := h.agents.Enroll(ctx, agent.ID, token, "-----BEGIN CERT-----\nfake\n-----END CERT-----",
		"fingerprint-1234"); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	enrolled, err := h.agents.Get(ctx, agent.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if enrolled.Status != "online" {
		t.Fatalf("expected online after enroll, got %s", enrolled.Status)
	}
	if enrolled.CertStatus != "issued" {
		t.Fatalf("expected cert_status=issued, got %s", enrolled.CertStatus)
	}

	// Replaying the token must fail (one-time).
	if err := h.agents.Enroll(ctx, agent.ID, token, "x", "x"); err == nil {
		t.Fatalf("expected token replay to fail")
	}

	// Heartbeat updates cpu / mem.
	if err := h.agents.Heartbeat(ctx, agents.Heartbeat{
		AgentID: agent.ID, CPUPercent: 32.5, MemoryPercent: 41.0,
		RunningJobs: 1, Version: "1.0.0",
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	after, _ := h.agents.Get(ctx, agent.ID)
	if after.CPUPercent < 32 || after.MemoryPercent < 40 {
		t.Fatalf("heartbeat didn't update agent state: %+v", after)
	}
	if after.LastHeartbeat == nil || time.Since(*after.LastHeartbeat) > time.Minute {
		t.Fatalf("last_heartbeat not updated")
	}
}
