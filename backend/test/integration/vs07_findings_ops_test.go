//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/findings"
)

func ingestFinding(t *testing.T, h *harness, tenantID, engagementID uuid.UUID, in findings.IngestInput) uuid.UUID {
	t.Helper()
	in.PlatformID = platformID
	in.PartnerID = directID
	in.TenantID = tenantID
	in.EngagementID = engagementID
	f, _, err := h.findings.Upsert(context.Background(), in)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return f.ID
}

// TestVS07_SimilarityClustering: three findings on different ports
// collapse into ONE cluster.
func TestVS07_SimilarityClustering(t *testing.T) {
	h := newHarness(t)
	tenantID, eng := h.makeTenant(t, "vs07-cluster")

	ports := []int{443, 8443, 9443}
	var ids []uuid.UUID
	for _, p := range ports {
		ids = append(ids, ingestFinding(t, h, tenantID, eng, findings.IngestInput{
			Title:    "Weak TLS protocol enabled on tcp/" + portStr(p),
			Severity: "high", Scanner: "testssl",
			Port: p, Protocol: "tcp",
			AffectedEndpoint: "globex.example",
		}))
	}

	// All three findings must share the same cluster_id.
	clusters := map[uuid.UUID]bool{}
	for _, id := range ids {
		var cl uuid.UUID
		if err := h.pool.QueryRow(context.Background(),
			`SELECT cluster_id FROM findings WHERE id=$1`, id).Scan(&cl); err != nil {
			t.Fatalf("cluster lookup: %v", err)
		}
		clusters[cl] = true
	}
	if len(clusters) != 1 {
		t.Fatalf("expected 1 shared cluster, got %d", len(clusters))
	}

	list, err := h.findings.ListClusters(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].MemberCount != 3 {
		t.Fatalf("expected one cluster with 3 members, got %+v", list)
	}
}

// TestVS07_SeverityOverride: a tenant rule "title=Weak TLS → critical"
// upgrades severity at ingest and stamps the override origin.
func TestVS07_SeverityOverride(t *testing.T) {
	h := newHarness(t)
	tenantID, eng := h.makeTenant(t, "vs07-sev")

	if _, err := h.findings.AddSeverityOverride(context.Background(), tenantID, &adminID,
		findings.SeverityOverrideInput{
			Name: "tls-critical", TitleRegex: "weak tls",
			NewSeverity: "critical", Reason: "regulator-mandated",
		}); err != nil {
		t.Fatalf("add override: %v", err)
	}

	id := ingestFinding(t, h, tenantID, eng, findings.IngestInput{
		Title: "Weak TLS protocol enabled", Severity: "medium",
		Scanner: "testssl",
	})
	var sev, from string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT severity, COALESCE(severity_overridden_from,'')
		   FROM findings WHERE id=$1`, id).Scan(&sev, &from); err != nil {
		t.Fatal(err)
	}
	if sev != "critical" {
		t.Fatalf("expected severity bumped to critical, got %s", sev)
	}
	if from != "medium" {
		t.Fatalf("expected severity_overridden_from=medium, got %s", from)
	}

	// A finding that doesn't match keeps its original severity.
	noMatchID := ingestFinding(t, h, tenantID, eng, findings.IngestInput{
		Title: "Unauthenticated SMB share", Severity: "low",
		Scanner: "nmap",
	})
	var sev2, from2 string
	_ = h.pool.QueryRow(context.Background(),
		`SELECT severity, COALESCE(severity_overridden_from,'')
		   FROM findings WHERE id=$1`, noMatchID).Scan(&sev2, &from2)
	if sev2 != "low" || from2 != "" {
		t.Fatalf("non-matching finding mutated: sev=%s from=%s", sev2, from2)
	}
}

// TestVS07_Suppression: rule for scanner=nmap + title="port closed"
// auto-suppresses ingested matches.
func TestVS07_Suppression(t *testing.T) {
	h := newHarness(t)
	tenantID, eng := h.makeTenant(t, "vs07-supp")
	if _, err := h.findings.AddSuppressionRule(context.Background(), tenantID, &adminID,
		findings.SuppressionInput{
			Name: "close-noise", ScannerFilter: "nmap",
			TitleRegex: "port .* closed",
			Reason:     "informational only",
		}); err != nil {
		t.Fatalf("add suppress: %v", err)
	}

	id := ingestFinding(t, h, tenantID, eng, findings.IngestInput{
		Title:    "Port 23 closed",
		Severity: "info", Scanner: "nmap",
		AffectedEndpoint: "10.0.0.1",
	})
	var status string
	var rule *uuid.UUID
	if err := h.pool.QueryRow(context.Background(),
		`SELECT status, suppression_rule_id FROM findings WHERE id=$1`, id).
		Scan(&status, &rule); err != nil {
		t.Fatal(err)
	}
	if status != "false_positive" {
		t.Fatalf("expected auto-suppressed false_positive, got %s", status)
	}
	if rule == nil {
		t.Fatal("suppression_rule_id not set")
	}

	// hit_count incremented.
	var hits int
	_ = h.pool.QueryRow(context.Background(),
		`SELECT hit_count FROM finding_suppression_rules WHERE id=$1`, *rule).Scan(&hits)
	if hits < 1 {
		t.Fatalf("expected hit_count >= 1, got %d", hits)
	}

	// A non-matching finding survives.
	keepID := ingestFinding(t, h, tenantID, eng, findings.IngestInput{
		Title: "Port 22 open", Severity: "low", Scanner: "nmap",
	})
	var status2 string
	_ = h.pool.QueryRow(context.Background(),
		`SELECT status FROM findings WHERE id=$1`, keepID).Scan(&status2)
	if status2 != "open" {
		t.Fatalf("non-matching finding got suppressed: %s", status2)
	}
}

// TestVS07_SARIFExport: two findings produce a SARIF doc with one Run
// per scanner.
func TestVS07_SARIFExport(t *testing.T) {
	h := newHarness(t)
	tenantID, eng := h.makeTenant(t, "vs07-sarif")
	_ = ingestFinding(t, h, tenantID, eng, findings.IngestInput{
		Title: "SSH weak ciphers", Severity: "medium", Scanner: "nmap",
		CVE: "CVE-2020-12345", AffectedEndpoint: "10.0.0.5", Port: 22, Protocol: "tcp",
	})
	_ = ingestFinding(t, h, tenantID, eng, findings.IngestInput{
		Title: "SQL injection in /login", Severity: "critical", Scanner: "zap",
		CWE: "CWE-89", AffectedEndpoint: "https://app.example/login",
	})

	body, err := h.findings.SARIFExport(context.Background(), findings.ListFilter{TenantID: tenantID})
	if err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if !strings.Contains(string(body), `"version": "2.1.0"`) {
		t.Fatalf("missing SARIF version in:\n%s", body)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string }
			}
			Results []struct{ RuleID, Level string }
		}
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("expected 2 runs (one per scanner), got %d", len(doc.Runs))
	}
	scanners := map[string]int{}
	for _, r := range doc.Runs {
		scanners[r.Tool.Driver.Name] = len(r.Results)
	}
	if scanners["nmap"] != 1 || scanners["zap"] != 1 {
		t.Fatalf("scanner result counts wrong: %+v", scanners)
	}
}

func portStr(p int) string {
	switch p {
	case 443:
		return "443"
	case 8443:
		return "8443"
	case 9443:
		return "9443"
	}
	return "0"
}
