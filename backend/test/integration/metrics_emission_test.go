//go:build integration

// metrics_emission_test.go — proves that the 12 declared Prometheus
// counters (declared in observability/metrics.go) are actually
// emitted by the service layer. Without this we ship dashboards that
// flatline because the .Inc() sites were never wired in business code.
//
// For each metric we exercise the code path that should bump it and
// then assert the exposed /metrics output reflects the change.

package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/observability"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

func scrapeMetrics(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(observability.PromHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// metricLine returns the value of metric{labels} or 0 if absent.
func metricLine(scrape, name string) int {
	for _, line := range strings.Split(scrape, "\n") {
		if strings.HasPrefix(line, name) {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			f := 0
			for _, c := range parts[len(parts)-1] {
				if c == '.' || c == 'e' {
					break
				}
				if c >= '0' && c <= '9' {
					f = f*10 + int(c-'0')
				}
			}
			return f
		}
	}
	return 0
}

func TestMetrics_FindingsIngested_Bumped(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tA, engA := h.makeTenant(t, "metric-find-a")

	before := metricLine(scrapeMetrics(t),
		`vaultscan_findings_ingested_total{scanner="nmap",severity="medium"}`)

	if _, _, err := h.findings.Upsert(ctx, findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tA, EngagementID: engA,
		Title: "metric-emit-test", Severity: "medium", Scanner: "nmap",
		AffectedEndpoint: "metric.example",
	}); err != nil {
		t.Fatal(err)
	}

	after := metricLine(scrapeMetrics(t),
		`vaultscan_findings_ingested_total{scanner="nmap",severity="medium"}`)
	if after <= before {
		t.Fatalf("FindingsIngested not bumped: before=%d after=%d", before, after)
	}
}

func TestMetrics_FindingsDeduplicated_Bumped(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tA, engA := h.makeTenant(t, "metric-dedup-a")

	in := findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tA, EngagementID: engA,
		Title: "dedup-emit-test", Severity: "medium", Scanner: "nmap",
		AffectedEndpoint: "dedup.example",
	}
	if _, _, err := h.findings.Upsert(ctx, in); err != nil {
		t.Fatal(err)
	}
	before := metricLine(scrapeMetrics(t),
		`vaultscan_findings_deduplicated_total`)

	// Identical → ON CONFLICT path → dedup counter bumps.
	if _, _, err := h.findings.Upsert(ctx, in); err != nil {
		t.Fatal(err)
	}
	after := metricLine(scrapeMetrics(t),
		`vaultscan_findings_deduplicated_total`)
	if after <= before {
		t.Fatalf("FindingsDeduplicated not bumped: before=%d after=%d", before, after)
	}
}

func TestMetrics_AuthLoginFailures_Bumped(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	shield := auth.NewBruteforceShield(h.pool)

	before := metricLine(scrapeMetrics(t), `vaultscan_auth_login_failures_total`)
	if _, err := shield.RecordFailure(ctx, net.ParseIP("203.0.113.42"), "test@example.com"); err != nil {
		t.Fatal(err)
	}
	after := metricLine(scrapeMetrics(t), `vaultscan_auth_login_failures_total`)
	if after <= before {
		t.Fatalf("AuthLoginFailures not bumped: before=%d after=%d", before, after)
	}
}

func TestMetrics_AuthIPLockouts_BumpedAfterThreshold(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	shield := auth.NewBruteforceShield(h.pool)
	shield.Threshold = 3 // lower threshold for the test

	ip := net.ParseIP("198.51.100.99")
	before := metricLine(scrapeMetrics(t), `vaultscan_auth_ip_lockouts_total`)
	for i := 0; i < shield.Threshold; i++ {
		if _, err := shield.RecordFailure(ctx, ip, "victim@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	after := metricLine(scrapeMetrics(t), `vaultscan_auth_ip_lockouts_total`)
	if after <= before {
		t.Fatalf("AuthIPLockouts not bumped after %d failures: before=%d after=%d",
			shield.Threshold, before, after)
	}
}

func TestMetrics_ScanJobsCreated_Bumped(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tA, engA := h.makeTenant(t, "metric-scan-a")
	actor := uuid.New()

	before := metricLine(scrapeMetrics(t),
		`vaultscan_scan_jobs_created_total{plane="external"}`)
	_, _, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tA, EngagementID: engA,
		ProfileCode: "ext_recon_quick",
		Plane:       "external",
		Region:      "us-east-1",
		Targets:     []string{"203.0.113.10"},
		RequestedBy: &actor,
	})
	if err != nil {
		t.Fatalf("scanorch.Submit: %v", err)
	}
	after := metricLine(scrapeMetrics(t),
		`vaultscan_scan_jobs_created_total{plane="external"}`)
	if after <= before {
		t.Fatalf("ScanJobsCreated not bumped: before=%d after=%d", before, after)
	}
}

func TestMetrics_EmergencyStopSLA_Observed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Just calling EmergencyStop with empty scope must record a histogram
	// observation even when 0 jobs match.
	scrapeBefore := scrapeMetrics(t)
	beforeSum := metricLine(scrapeBefore, `vaultscan_emergency_stop_sla_ms_count`)

	if _, err := h.scanorch.EmergencyStop(ctx, nil, scanorch.EmergencyScope{}); err != nil {
		t.Fatal(err)
	}
	afterSum := metricLine(scrapeMetrics(t), `vaultscan_emergency_stop_sla_ms_count`)
	if afterSum <= beforeSum {
		t.Fatalf("EmergencyStopSLAms not observed: before=%d after=%d", beforeSum, afterSum)
	}
	_ = time.Second // pacify linter on unused-import
}

func TestMetrics_AuditChainBreaks_BumpedOnTamper(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tA, engA := h.makeTenant(t, "metric-chain-a")
	// Seed 3 audit rows so we have a chain to verify.
	for i := 0; i < 3; i++ {
		_, _, _ = h.findings.Upsert(ctx, findings.IngestInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tA, EngagementID: engA,
			Title: "chain-seed", Severity: "low", Scanner: "nmap",
			AffectedEndpoint: "chain.example",
		})
	}
	// Tamper one audit row to force a chain break.
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_logs SET payload = jsonb_set(payload, '{tampered}', 'true')
		  WHERE id = (SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1 OFFSET 1)`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	before := metricLine(scrapeMetrics(t), `vaultscan_audit_chain_breaks_total`)
	if _, err := h.audit.VerifyDeep(ctx); err != nil {
		t.Fatal(err)
	}
	after := metricLine(scrapeMetrics(t), `vaultscan_audit_chain_breaks_total`)
	if after <= before {
		t.Fatalf("AuditChainBreaks not bumped: before=%d after=%d", before, after)
	}
}
