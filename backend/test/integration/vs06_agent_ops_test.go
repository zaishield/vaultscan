//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/agents"
)

// TestVS06_CSRRotation: agent submits a CSR, backend issues a fresh
// cert, old cert is revoked, agent_csr_requests row points at the new
// cert id.
func TestVS06_CSRRotation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs06-rot")

	agent, token, err := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "agent-rot", FormFactor: "linux_vm", CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Initial enroll plants a placeholder cert.
	if err := h.agents.Enroll(ctx, agent.ID, token,
		"-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----",
		"old-fingerprint"); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Generate a fresh agent key + CSR.
	agentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent-rot.vaultscan.example"},
	}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	ca, err := agents.NewSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}
	newCert, fp, err := h.agents.SubmitCSR(ctx, agent.ID, string(csrPEM), ca)
	if err != nil {
		t.Fatalf("submit csr: %v", err)
	}
	if fp == "" || newCert == "" {
		t.Fatalf("empty cert/fingerprint")
	}

	// Old cert is now revoked, exactly one live cert remains.
	var live int
	_ = h.pool.QueryRow(ctx,
		`SELECT count(*) FROM agent_certificates
		  WHERE agent_id=$1 AND revoked_at IS NULL`, agent.ID).Scan(&live)
	if live != 1 {
		t.Fatalf("expected exactly one live cert after rotation, got %d", live)
	}

	// CSR row links to the new cert.
	var status string
	var issuedCert uuid.UUID
	if err := h.pool.QueryRow(ctx,
		`SELECT status, issued_cert_id FROM agent_csr_requests WHERE agent_id=$1`,
		agent.ID).Scan(&status, &issuedCert); err != nil {
		t.Fatalf("csr row: %v", err)
	}
	if status != "issued" || issuedCert == uuid.Nil {
		t.Fatalf("csr not issued, status=%s cert=%s", status, issuedCert)
	}

	// Tampered CSR (signature won't verify) — should be rejected without
	// minting a cert.
	mangled := []byte(string(csrPEM))
	// Flip a byte inside the base64 body to break the signature.
	for i := 100; i < len(mangled); i++ {
		if mangled[i] == 'A' {
			mangled[i] = 'B'
			break
		}
	}
	if _, _, err := h.agents.SubmitCSR(ctx, agent.ID, string(mangled), ca); err == nil {
		t.Fatalf("tampered CSR must be rejected")
	}
}

// TestVS06_Telemetry: insert several heartbeats, run RollupTelemetry,
// observe avg/peak buckets in agent_telemetry_rollups.
func TestVS06_Telemetry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs06-tel")
	agent, _, err := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "agent-tel", FormFactor: "linux_vm", CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed 6 heartbeats across two 5-minute buckets.
	now := time.Now().UTC().Truncate(5 * time.Minute)
	rows := []struct {
		off time.Duration
		cpu float64
		mem float64
		q   int
	}{
		{-9 * time.Minute, 20, 30, 1},
		{-8 * time.Minute, 40, 50, 3},
		{-7 * time.Minute, 60, 70, 5},
		{-4 * time.Minute, 10, 15, 0},
		{-3 * time.Minute, 12, 18, 2},
		{-1 * time.Minute, 90, 95, 9},
	}
	for _, r := range rows {
		if _, err := h.pool.Exec(ctx, `
			INSERT INTO agent_heartbeats(agent_id, received_at, cpu_percent,
			    memory_percent, disk_percent, running_jobs, queue_depth)
			VALUES ($1, $2, $3, $4, 0, 0, $5)`,
			agent.ID, now.Add(r.off), r.cpu, r.mem, r.q); err != nil {
			t.Fatal(err)
		}
	}

	written, err := h.agents.RollupTelemetry(ctx, agent.ID,
		now.Add(-30*time.Minute), now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if written < 2 {
		t.Fatalf("expected at least two buckets written, got %d", written)
	}
	bs, err := h.agents.ListTelemetry(ctx, agent.ID, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bs) < 2 {
		t.Fatalf("expected at least 2 rollups, got %d", len(bs))
	}
	// Highest-cpu bucket must reflect the 90% sample.
	highest := 0.0
	maxQ := 0
	for _, b := range bs {
		if b.CPUPeak > highest {
			highest = b.CPUPeak
		}
		if b.QueuePeak > maxQ {
			maxQ = b.QueuePeak
		}
	}
	if highest < 89 || highest > 91 {
		t.Fatalf("expected cpu peak ~90, got %.2f", highest)
	}
	if maxQ != 9 {
		t.Fatalf("expected queue peak 9, got %d", maxQ)
	}
}

// TestVS06_SignedBundle: publish a signed manifest; agent fetches via
// OfferUpdate; manifest signature verifies; tampered payload rejected.
func TestVS06_SignedBundle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs06-bun")
	agent, _, _ := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "agent-bundle", FormFactor: "linux_vm", CreatedBy: &adminID,
	})

	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := agents.UpdateBundleManifest{
		TargetVersion:   "1.2.0",
		DownloadURL:     "https://updates.zaishield.com/agent-1.2.0.tar.gz",
		BundleSHA256:    "abc123",
		IssuedAt:        time.Now().UTC().Format(time.RFC3339),
		MinFromVersion:  "1.0.0",
	}
	body := agents.CanonicalManifestBytes(m)
	sig, err := agents.SignBundleManifest(body, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.agents.PublishBundle(ctx, m, sig, "agent-ca-1", ""); err != nil {
		t.Fatalf("publish: %v", err)
	}

	off, err := h.agents.OfferUpdate(ctx, agent.ID, "1.1.0")
	if err != nil || off == nil {
		t.Fatalf("offer: err=%v offer=%v", err, off)
	}
	if off.Manifest.TargetVersion != "1.2.0" {
		t.Fatalf("expected 1.2.0, got %s", off.Manifest.TargetVersion)
	}

	// Signature verifies under signer's public key.
	canon, _ := json.Marshal(off.Manifest)
	if err := agents.VerifyBundleSig(canon, off.Signature, &signerKey.PublicKey); err != nil {
		t.Fatalf("legit sig must verify: %v", err)
	}

	// Tampered manifest fails.
	bad := off.Manifest
	bad.DownloadURL = "https://evil.example/agent.tar.gz"
	badBytes, _ := json.Marshal(bad)
	if err := agents.VerifyBundleSig(badBytes, off.Signature, &signerKey.PublicKey); err == nil {
		t.Fatal("tampered manifest must fail signature verify")
	}

	// MinFromVersion gating: agent on 0.9.x must NOT be offered the bundle.
	off2, err := h.agents.OfferUpdate(ctx, agent.ID, "0.9.0")
	if err != nil {
		t.Fatal(err)
	}
	if off2 != nil {
		t.Fatalf("agent at 0.9.0 must not be offered 1.2.0 (min_from=1.0.0)")
	}
}

// TestVS06_EmergencyStopSLA: arrival → ack within 50ms computes a sub-
// second SLA, breach counter stays at 0.
func TestVS06_EmergencyStopSLA(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs06-emr")
	agent, _, _ := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "agent-em", FormFactor: "linux_vm", CreatedBy: &adminID,
	})

	// Three quick stop cycles.
	for i := 0; i < 3; i++ {
		id, err := h.agents.RequestEmergencyStop(ctx, agent.ID, "operator drill", "agent", &adminID)
		if err != nil {
			t.Fatalf("request stop: %v", err)
		}
		time.Sleep(20 * time.Millisecond) // simulate the round-trip
		if err := h.agents.AckEmergencyStop(ctx, id); err != nil {
			t.Fatalf("ack: %v", err)
		}
	}

	stats, err := h.agents.EmergencyStopSLAStats(ctx, agent.ID,
		time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Count != 3 {
		t.Fatalf("expected 3 samples, got %d", stats.Count)
	}
	if stats.BreachCount != 0 {
		t.Fatalf("expected 0 SLA breaches, got %d", stats.BreachCount)
	}
	if stats.AvgMs > 5000 {
		t.Fatalf("avg too high: %.1fms", stats.AvgMs)
	}
	if stats.P95Ms <= 0 {
		t.Fatalf("p95 must be positive, got %d", stats.P95Ms)
	}
}
