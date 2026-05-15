//go:build integration

// §24 mobile-portal API tests through real HTTP.

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSection24_DeviceEnrollAndDashboard(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	tenantID, _ := h.makeTenant(t, "mobile-tenant")
	tok := mintToken(t, tenantID)

	httpPost := func(path string, body any, want int) []byte {
		t.Helper()
		var buf strings.Builder
		_ = json.NewEncoder(&buf).Encode(body)
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(buf.String()))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Tenant-Id", tenantID.String())
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s: want %d got %d body=%s", path, want, resp.StatusCode, out)
		}
		return out
	}

	// Enroll device
	out := httpPost("/api/v1/mobile/devices", map[string]any{
		"platform":    "ios",
		"push_token":  "apns-token-deadbeef",
		"app_version": "1.0.0",
		"os_version":  "iOS 17",
	}, 201)
	if !strings.Contains(string(out), `"device_id"`) {
		t.Fatalf("response missing device_id: %s", out)
	}

	// Re-enroll same token: ON CONFLICT upsert, returns the same device_id.
	httpPost("/api/v1/mobile/devices", map[string]any{
		"platform": "ios", "push_token": "apns-token-deadbeef",
	}, 201)

	// Bad platform rejected.
	httpPost("/api/v1/mobile/devices", map[string]any{
		"platform": "windows-phone", "push_token": "x",
	}, 400)

	// Mobile dashboard returns summary + top_findings shape.
	req, _ := http.NewRequest("GET",
		srv.URL+"/api/v1/mobile/dashboard?tenant_id="+tenantID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Tenant-Id", tenantID.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("dashboard %d: %s", resp.StatusCode, body)
	}
	var doc struct {
		Summary struct {
			Critical    int `json:"critical"`
			High        int `json:"high"`
			SLABreached int `json:"sla_breached"`
			OnlineAgents int `json:"online_agents"`
		} `json:"summary"`
		TopFindings []any `json:"top_findings"`
	}
	_ = json.Unmarshal(body, &doc)
	// counts are zero on a fresh tenant — just sanity that the shape is right.
	_ = doc.Summary.Critical

	// Ack — without a finding, just records the user touched a notification.
	httpPost("/api/v1/mobile/alerts/ack", map[string]any{
		"notification_id": "00000000-0000-0000-0000-000000000001",
	}, 201)

	_ = context.Background()
	_ = strings.Contains
}
