//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/cosign"
	"github.com/zaishield/vaultscan/backend/internal/scanner"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

// TestScannerWorker_EndToEnd exercises the full external-scan plane:
//
//   1. An orchestrator-signed scan job lands in scan_jobs status='dispatched'.
//   2. The scanner worker claims it (FOR UPDATE SKIP LOCKED).
//   3. The signature is verified against the orchestrator's public key.
//   4. The synthetic runner produces nmap-shaped output for the target.
//   5. The output is stored encrypted in the evidence vault.
//   6. The Nmap parser ingests one finding per open port.
//   7. The job is marked succeeded.
func TestScannerWorker_EndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "scanner-e2e")

	// Approve a CIDR scope so Scope Guard lets the job through.
	scope, err := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "approved by test")
	if err != nil {
		t.Fatalf("add scope: %v", err)
	}
	if err := h.engagements.ApproveScope(ctx, &adminID, scope.ID); err != nil {
		t.Fatalf("approve scope: %v", err)
	}
	if err := h.engagements.Activate(ctx, &adminID, engagementID); err != nil {
		t.Fatalf("activate engagement: %v", err)
	}

	job, _, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		EngagementID: engagementID,
		ProfileCode:  "external_standard_va",
		Plane:        "external",
		Region:       "ae",
		Targets:      []string{"203.0.113.42"},
		RequestedBy:  &adminID,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if job.Status != "dispatched" {
		t.Fatalf("expected dispatched, got %s", job.Status)
	}
	if job.JobSignature == "" {
		t.Fatalf("expected signed job, got empty signature")
	}

	// Use the matching public key so signature verification succeeds.
	pubPEM, err := h.signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	log := zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel)
	w := scanner.NewWorker(log, h.pool, scanner.Config{
		Region:        "ae",
		SignerPubPEM:  pubPEM,
		Poll:          200 * time.Millisecond,
		MaxConcurrent: 1,
		// RequireSignatures stays false so this happy-path test exercises
		// the legacy soft-pass: no cosign bundle cached on the registry rows.
	}, h.vault, h.findings, h.audit, h.bus, cosign.New(h.pool))

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	go w.Run(ctx2)

	deadline := time.Now().Add(10 * time.Second)
	var status string
	var findingCount int
	for time.Now().Before(deadline) {
		_ = h.pool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE id=$1`, job.ID).Scan(&status)
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings WHERE scan_job_id=$1`, job.ID).Scan(&findingCount)
		if status == "succeeded" && findingCount >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status != "succeeded" {
		t.Fatalf("expected job status 'succeeded', got %q (findings=%d)", status, findingCount)
	}
	if findingCount < 1 {
		t.Fatalf("expected >= 1 finding ingested, got %d", findingCount)
	}

	// Evidence row must exist and be encrypted.
	var encrypted bool
	if err := h.pool.QueryRow(ctx,
		`SELECT encrypted FROM finding_evidence WHERE scan_job_id=$1 LIMIT 1`, job.ID).
		Scan(&encrypted); err != nil {
		t.Fatalf("evidence row: %v", err)
	}
	if !encrypted {
		t.Fatalf("evidence row not flagged encrypted")
	}
}

// TestScannerWorker_RejectsTamperedSignature uses a different key pair to
// build a signed manifest, then proves the worker refuses the job and marks
// it failed.
func TestScannerWorker_RejectsTamperedSignature(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, engagementID := h.makeTenant(t, "scanner-tamper")
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "198.51.100.0/24", "external", "")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	job, _, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		EngagementID: engagementID,
		ProfileCode:  "external_standard_va",
		Plane:        "external",
		Region:       "us",
		Targets:      []string{"198.51.100.7"},
		RequestedBy:  &adminID,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Build a worker that trusts an UNRELATED key. The orchestrator signed
	// with `h.signer`; we hand the worker a fresh signer's public key, so
	// verification must fail.
	wrongSigner, _ := scanorch.NewSigner("not-the-real-signer", "")
	wrongPub, _ := wrongSigner.PublicKeyPEM()

	log := zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel)
	w := scanner.NewWorker(log, h.pool, scanner.Config{
		Region:        "us",
		SignerPubPEM:  wrongPub,
		Poll:          200 * time.Millisecond,
		MaxConcurrent: 1,
	}, h.vault, h.findings, h.audit, h.bus, cosign.New(h.pool))

	ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	go w.Run(ctx2)

	deadline := time.Now().Add(5 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		_ = h.pool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE id=$1`, job.ID).Scan(&status)
		if status == "failed" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status != "failed" {
		t.Fatalf("expected job status 'failed' (signature rejected), got %q", status)
	}

	// No findings should have been ingested for a rejected job.
	var findingCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings WHERE scan_job_id=$1`, job.ID).Scan(&findingCount)
	if findingCount != 0 {
		t.Fatalf("expected 0 findings for rejected job, got %d", findingCount)
	}
}
