//go:build integration

// §21 Cloud posture: connect → scan → drift.

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/cloudposture"
)

func TestCloudPosture_SnapshotAndDrift(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "cp-drift")

	svc := cloudposture.New(h.pool)
	first := cloudposture.NewStaticAdapter("aws", []cloudposture.ControlResult{
		{ControlID: "CIS-AWS-1.1", Status: "pass", Severity: "high", Title: "Root account MFA"},
		{ControlID: "CIS-AWS-1.5", Status: "fail", Severity: "high", Title: "MFA on admin users"},
		{ControlID: "CIS-AWS-2.1", Status: "pass", Severity: "medium", Title: "CloudTrail enabled"},
	})
	svc.RegisterAdapter(first)

	accountID, err := svc.ConnectAccount(ctx, cloudposture.ConnectInput{
		TenantID: tenantID, Provider: "aws", AccountLabel: "prod",
		ExternalID: "123456789012", CredentialRef: "secrets/aws/prod",
		RoleARN: "arn:aws:iam::123456789012:role/vaultscan-reader",
		Regions: []string{"us-east-1", "eu-west-1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// First snapshot — no drift yet (nothing prior to compare).
	snap1, err := svc.Snapshot(ctx, accountID)
	if err != nil {
		t.Fatalf("snap1: %v", err)
	}
	if snap1 == uuid.Nil {
		t.Fatal("snapshot id missing")
	}
	results, score, err := svc.LatestSnapshot(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || score < 60 || score > 70 {
		t.Fatalf("expected ~66.6 score with 3 results, got %f / %d results", score, len(results))
	}

	// Second adapter with a regression on CIS-AWS-2.1.
	second := cloudposture.NewStaticAdapter("aws", []cloudposture.ControlResult{
		{ControlID: "CIS-AWS-1.1", Status: "pass", Severity: "high", Title: "Root account MFA"},
		{ControlID: "CIS-AWS-1.5", Status: "pass", Severity: "high", Title: "MFA on admin users"}, // improved
		{ControlID: "CIS-AWS-2.1", Status: "fail", Severity: "medium", Title: "CloudTrail enabled"},  // regressed
	})
	// Re-register so the same provider key now points at the new adapter.
	svc.RegisterAdapter(second)

	if _, err := svc.Snapshot(ctx, accountID); err != nil {
		t.Fatalf("snap2: %v", err)
	}

	drift, err := svc.DriftSince(ctx, accountID, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 2 {
		t.Fatalf("expected 2 drift events (one each direction), got %d: %+v", len(drift), drift)
	}
	byCtrl := map[string]string{}
	for _, d := range drift {
		byCtrl[d.ControlID] = d.Direction
	}
	if byCtrl["CIS-AWS-1.5"] != "improved" {
		t.Fatalf("CIS-AWS-1.5 should be improved, got %s", byCtrl["CIS-AWS-1.5"])
	}
	if byCtrl["CIS-AWS-2.1"] != "regressed" {
		t.Fatalf("CIS-AWS-2.1 should be regressed, got %s", byCtrl["CIS-AWS-2.1"])
	}
}

func TestCloudPosture_RejectsUnknownProvider(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "cp-unknown")
	svc := cloudposture.New(h.pool)
	accountID, err := svc.ConnectAccount(ctx, cloudposture.ConnectInput{
		TenantID: tenantID, Provider: "exotic-cloud",
		AccountLabel: "test", ExternalID: "x",
		CredentialRef: "secrets/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Snapshot(ctx, accountID)
	if err == nil {
		t.Fatal("expected snapshot to fail with no adapter registered")
	}
}
