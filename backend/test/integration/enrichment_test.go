//go:build integration

// §14 (discovery) + §16 (vulnerability) enrichment.

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/enrichment"
)

func TestEnrichment_ShodanMatchesByHostname(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "enrich-shodan")
	// Insert one asset by hostname.
	var assetID string
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO assets(platform_id, partner_id, tenant_id, asset_type,
		    value, name, plane, criticality, discovered_via)
		VALUES ($1, $2, $3, 'subdomain', 'api.globex.example', 'api.globex.example',
		        'external', 'unknown', 'manual')
		RETURNING id`, platformID, directID, tenantID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}

	e := enrichment.NewDiscoveryEnricher(h.pool)
	matched, unmatched, err := e.ImportShodan(ctx, tenantID, []enrichment.ShodanHost{
		{
			IP:        "203.0.113.10",
			Hostnames: []string{"api.globex.example"},
			Ports:     []int{443, 8443},
			Org:       "Globex Corp",
		},
		{
			IP:        "198.51.100.5",
			Hostnames: []string{"unknown.invalid"},
		},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if matched != 1 || unmatched != 1 {
		t.Fatalf("expected 1 matched + 1 unmatched, got %d/%d", matched, unmatched)
	}

	// Verify open_ports + services + metadata rows landed.
	var attrCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT count(*) FROM asset_enrichments WHERE asset_id=$1 AND source='shodan'`,
		assetID).Scan(&attrCount)
	if attrCount < 3 {
		t.Fatalf("expected 3 shodan enrichment rows, got %d", attrCount)
	}

	// open_ports JSON contains the right values.
	var portsRaw string
	_ = h.pool.QueryRow(ctx,
		`SELECT value::text FROM asset_enrichments
		  WHERE asset_id=$1 AND attribute='open_ports'`, assetID).Scan(&portsRaw)
	if !strings.Contains(portsRaw, "443") || !strings.Contains(portsRaw, "8443") {
		t.Fatalf("open_ports JSON missing ports: %s", portsRaw)
	}
}

func TestEnrichment_CTLogAutoDiscoversSubdomains(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "enrich-ct")

	e := enrichment.NewDiscoveryEnricher(h.pool)
	_, _, err := e.ImportCT(ctx, tenantID, []enrichment.CTEntry{
		{
			CommonName: "newdomain.globex.example",
			SANNames:   []string{"newdomain.globex.example\napi-v2.globex.example"},
			Issuer:     "Let's Encrypt R3",
			Serial:     "abc123",
		},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	// Two SANs → two assets auto-created.
	var count int
	_ = h.pool.QueryRow(ctx, `
		SELECT count(*) FROM assets
		 WHERE tenant_id=$1 AND discovered_via='ct_log'
		   AND value IN ('newdomain.globex.example','api-v2.globex.example')`,
		tenantID).Scan(&count)
	if count != 2 {
		t.Fatalf("expected 2 auto-discovered assets, got %d", count)
	}
	// Idempotent — re-import doesn't duplicate.
	_, dedup, _ := e.ImportCT(ctx, tenantID, []enrichment.CTEntry{
		{CommonName: "newdomain.globex.example", Serial: "abc123",
			SANNames: []string{"newdomain.globex.example"}},
	})
	if dedup != 1 {
		t.Fatalf("expected dedup on re-import, got %d", dedup)
	}
}

func TestEnrichment_KEVBumpsSeverityToCritical(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cv := enrichment.NewCVEEnricher(h.pool)

	kev := []byte(`{
		"vulnerabilities": [
			{"cveID":"CVE-2024-0001","vendorProject":"Acme","product":"webapp",
			 "vulnerabilityName":"Pre-auth RCE","dateAdded":"2024-01-15",
			 "shortDescription":"RCE in Acme webapp","requiredAction":"Patch",
			 "dueDate":"2024-02-05","knownRansomwareCampaignUse":"Known"}
		]
	}`)
	n, err := cv.LoadKEV(ctx, kev)
	if err != nil || n != 1 {
		t.Fatalf("LoadKEV: n=%d err=%v", n, err)
	}

	r, err := cv.LookupCVE(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if !r.KEV || !r.KEVRansomware {
		t.Fatalf("expected KEV+ransomware true, got %+v", r)
	}
	bump := cv.SeverityBump("medium", r)
	if bump != "critical" {
		t.Fatalf("KEV-flagged should bump to critical, got %q", bump)
	}
}

func TestEnrichment_EPSSHighPercentileBumpsToHigh(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cv := enrichment.NewCVEEnricher(h.pool)

	csv := `cve,epss,percentile
CVE-2024-0002,0.92,0.98
CVE-2024-0003,0.001,0.10
`
	n, err := cv.LoadEPSS(ctx, strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 rows, got %d", n)
	}
	r, _ := cv.LookupCVE(ctx, "CVE-2024-0002")
	if bump := cv.SeverityBump("low", r); bump != "high" {
		t.Fatalf("EPSS percentile 0.98 should bump low→high, got %q", bump)
	}
	r2, _ := cv.LookupCVE(ctx, "CVE-2024-0003")
	if bump := cv.SeverityBump("low", r2); bump != "" {
		t.Fatalf("EPSS 0.10 should not bump, got %q", bump)
	}
}

func TestEnrichment_NVDLoadsCVSS(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cv := enrichment.NewCVEEnricher(h.pool)

	nvd := []byte(`{
		"CVE_Items": [{
			"cve":{
				"CVE_data_meta":{"ID":"CVE-2024-0004"},
				"description":{"description_data":[{"lang":"en","value":"SQL injection in foo"}]},
				"references":{"reference_data":[{"url":"https://example.com/cve"}]}
			},
			"impact":{"baseMetricV3":{"cvssV3":{
				"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"baseScore":9.8,"baseSeverity":"CRITICAL"}}},
			"publishedDate":"2024-01-10T00:00:00Z",
			"lastModifiedDate":"2024-01-12T00:00:00Z"
		}]
	}`)
	n, err := cv.LoadNVD(ctx, nvd)
	if err != nil || n != 1 {
		t.Fatalf("LoadNVD: n=%d err=%v", n, err)
	}
	r, _ := cv.LookupCVE(ctx, "CVE-2024-0004")
	if r.CVSS != 9.8 {
		t.Fatalf("expected CVSS 9.8, got %f", r.CVSS)
	}
	if !strings.Contains(r.Summary, "SQL injection") {
		t.Fatalf("summary missing: %q", r.Summary)
	}
	if bump := cv.SeverityBump("medium", r); bump != "critical" {
		t.Fatalf("CVSS 9.8 should bump medium→critical, got %q", bump)
	}
}
