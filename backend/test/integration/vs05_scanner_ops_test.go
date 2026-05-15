//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

// TestVS05_HeartbeatRecoversDegraded: a node previously marked degraded
// becomes 'online' again once it produces a clean heartbeat.
func TestVS05_HeartbeatRecoversDegraded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	nodeID := h.makeScannerNode(t, "vs05-rec")
	// Force degrade.
	if _, err := h.pool.Exec(ctx,
		`UPDATE scanner_node_registry SET status='degraded' WHERE id=$1`,
		nodeID); err != nil {
		t.Fatalf("seed degrade: %v", err)
	}

	if err := h.nodes.RecordHeartbeat(ctx, scanorch.Heartbeat{
		NodeID: nodeID, InflightJobs: 0, LoadAvg: 0.5,
		KernelVersion: "6.10.0", ScannerVersion: "0.1.0",
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	var status string
	if err := h.pool.QueryRow(ctx,
		`SELECT status FROM scanner_node_registry WHERE id=$1`,
		nodeID).Scan(&status); err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != "online" {
		t.Fatalf("expected online after clean heartbeat, got %s", status)
	}
}

// TestVS05_FailoverThreshold: three consecutive failing heartbeats
// auto-degrade the node and write a failover audit row.
func TestVS05_FailoverThreshold(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	nodeID := h.makeScannerNode(t, "vs05-fail")
	for i := 0; i < 3; i++ {
		if err := h.nodes.RecordHeartbeat(ctx, scanorch.Heartbeat{
			NodeID: nodeID, LastError: "image pull denied: unauthorized",
		}); err != nil {
			t.Fatalf("hb %d: %v", i, err)
		}
	}
	var status string
	if err := h.pool.QueryRow(ctx,
		`SELECT status FROM scanner_node_registry WHERE id=$1`,
		nodeID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "degraded" {
		t.Fatalf("expected node degraded after 3 failures, got %s", status)
	}
	var failovers int
	_ = h.pool.QueryRow(ctx,
		`SELECT count(*) FROM scanner_node_failovers WHERE node_id=$1`,
		nodeID).Scan(&failovers)
	if failovers < 1 {
		t.Fatalf("expected failover audit row, got %d", failovers)
	}
}

// TestVS05_FailoverStalled: the cron sweep degrades a node whose last
// heartbeat is older than StaleAfter.
func TestVS05_FailoverStalled(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	nodeID := h.makeScannerNode(t, "vs05-stall")
	// Insert a stale health row.
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO scanner_node_health(node_id, last_heartbeat_at, inflight_jobs)
		VALUES ($1, now() - interval '10 minutes', 0)
		ON CONFLICT (node_id) DO UPDATE
		SET last_heartbeat_at = EXCLUDED.last_heartbeat_at`,
		nodeID); err != nil {
		t.Fatalf("seed stale health: %v", err)
	}

	degraded, err := h.nodes.FailoverStalled(ctx)
	if err != nil {
		t.Fatalf("failover sweep: %v", err)
	}
	hit := false
	for _, id := range degraded {
		if id == nodeID {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected stalled node %s to be in degraded set, got %v",
			nodeID, degraded)
	}
}

// TestVS05_RegionQuotaBlocks: with a quota of 1, dispatching one job ties
// up the slot; the next pick returns ErrRegionAtQuota.
func TestVS05_RegionQuotaBlocks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs05-quota")

	if err := h.nodes.SetRegionQuota(ctx, "ae", 1, 0); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(ctx, `DELETE FROM scanner_region_quotas WHERE region='ae'`)
	})

	// Seed one dispatched job in the region — fills the slot.
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO scan_jobs(platform_id, partner_id, tenant_id, engagement_id,
		    profile_id, plane, region, status, target_summary, targets,
		    job_signature, signing_key_id)
		VALUES ($1, $2, $3,
		    (SELECT id FROM engagements WHERE tenant_id=$3 LIMIT 1),
		    (SELECT id FROM scan_profiles WHERE code='external_standard_va'),
		    'external','ae','dispatched','x.example',
		    '["x.example"]'::jsonb, '', '')`,
		platformID, directID, tenantID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	atQuota, q, err := h.nodes.IsRegionAtQuota(ctx, "ae", false)
	if err != nil {
		t.Fatalf("quota check: %v", err)
	}
	if !atQuota || q.Inflight < 1 {
		t.Fatalf("expected ae at quota with 1 inflight, got at=%v inflight=%d max=%d",
			atQuota, q.Inflight, q.MaxConcurrentJobs)
	}
}

// TestVS05_EligibleNodePicksLowestLoad: among two healthy nodes in the
// same region the picker returns the one with fewer inflight jobs.
func TestVS05_EligibleNodePicksLowestLoad(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	region := "vs05-pick"
	a := h.makeScannerNodeInRegion(t, "vs05-pick-a", region)
	b := h.makeScannerNodeInRegion(t, "vs05-pick-b", region)

	_ = h.nodes.RecordHeartbeat(ctx, scanorch.Heartbeat{NodeID: a, InflightJobs: 5})
	_ = h.nodes.RecordHeartbeat(ctx, scanorch.Heartbeat{NodeID: b, InflightJobs: 1})

	picked, err := h.nodes.EligibleNode(ctx, region)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if picked != b {
		t.Fatalf("expected lowest-load node %s, got %s", b, picked)
	}
}

// TestVS05_PullCredentialRoundtrip: store + retrieve recovers the same
// cleartext, and stored bytes don't contain the password verbatim.
func TestVS05_PullCredentialRoundtrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.nodes.UpsertPullCredential(ctx, &adminID, scanorch.PullCredential{
		Region: "ae", RegistryHost: "registry.zaishield.com",
		Username: "scanner-puller", Password: "s3cr3t-token-9!",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := h.nodes.GetPullCredential(ctx, "ae", "registry.zaishield.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Password != "s3cr3t-token-9!" {
		t.Fatalf("password roundtrip mismatch: got %q", got.Password)
	}

	// At-rest bytes must NOT contain the plaintext.
	var ct []byte
	_ = h.pool.QueryRow(ctx, `
		SELECT encrypted_secret FROM scanner_pull_credentials
		 WHERE region='ae' AND registry_host='registry.zaishield.com'`).Scan(&ct)
	if strings.Contains(string(ct), "s3cr3t-token-9!") {
		t.Fatal("password leaked in at-rest blob — encryption broken")
	}

	doc, err := h.nodes.DockerConfigJSON(ctx, "ae", "registry.zaishield.com")
	if err != nil {
		t.Fatalf("dockerconfigjson: %v", err)
	}
	if !strings.Contains(string(doc), "scanner-puller") {
		t.Fatalf("dockerconfigjson missing username: %s", doc)
	}
}

// TestVS05_NetworkPolicyYAML: the renderer produces a NetworkPolicy with
// every enabled rule for the region. Seed migration already inserts
// 'allow-https-out' and 'allow-dns-out' for every seed region.
func TestVS05_NetworkPolicyYAML(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	yaml, err := h.nodes.RenderNetworkPolicyYAML(ctx, "ae")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"kind: NetworkPolicy",
		"vaultscan.zaishield.com/region: ae",
		"# allow-dns-out",
		"# allow-https-out",
		"port: 443",
		"port: 53",
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("rendered YAML missing %q\n---\n%s", want, yaml)
		}
	}

	// Deterministic output: render twice, expect byte-identical.
	yaml2, _ := h.nodes.RenderNetworkPolicyYAML(ctx, "ae")
	if yaml != yaml2 {
		t.Fatal("renderer is not byte-deterministic")
	}
}

// ----- harness helpers ------------------------------------------------------

func (h *harness) makeScannerNode(t *testing.T, hostname string) uuid.UUID {
	t.Helper()
	return h.makeScannerNodeInRegion(t, hostname, "vs05-test")
}

func (h *harness) makeScannerNodeInRegion(t *testing.T, hostname, region string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := h.pool.Exec(context.Background(), `
		INSERT INTO scanner_node_registry(id, region, hostname, public_ip,
		    capacity_jobs, cpu_cores, memory_mb, abuse_contact, reverse_dns,
		    status, last_heartbeat)
		VALUES ($1, $2, $3, '203.0.113.99', 8, 16, 65536,
		    'abuse@test', $3, 'online', now())`,
		id, region, hostname); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM scanner_node_registry WHERE id=$1`, id)
	})
	return id
}

var _ = time.Second
