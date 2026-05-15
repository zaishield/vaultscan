//go:build integration

// §34 Marketplace: list catalog → install (pending_config) →
// configure (active) → uninstall (suspended).

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSection34_MarketplaceLifecycle(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	tenantID, _ := h.makeTenant(t, "mp-tenant")
	tok := mintToken(t, tenantID)

	do := func(method, path string, body any, want int) []byte {
		t.Helper()
		var reader io.Reader
		if body != nil {
			var buf bytes.Buffer
			_ = json.NewEncoder(&buf).Encode(body)
			reader = &buf
		}
		req, _ := http.NewRequest(method, srv.URL+path, reader)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Tenant-Id", tenantID.String())
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: want %d got %d body=%s",
				method, path, want, resp.StatusCode, out)
		}
		return out
	}

	// 1. Catalog has the seeded entries.
	body := do("GET", "/api/v1/marketplace/listings", nil, 200)
	var catalog struct {
		Listings []struct {
			ID              string `json:"id"`
			Slug            string `json:"slug"`
			IntegrationType string `json:"integration_type"`
			Verified        bool   `json:"verified"`
		} `json:"listings"`
	}
	_ = json.Unmarshal(body, &catalog)
	if len(catalog.Listings) < 5 {
		t.Fatalf("expected >=5 seeded listings, got %d", len(catalog.Listings))
	}
	bySlug := map[string]string{}
	for _, l := range catalog.Listings {
		bySlug[l.Slug] = l.ID
	}
	if bySlug["slack-incident-feed"] == "" {
		t.Fatal("missing slack-incident-feed")
	}

	// 2. Filter by category.
	chat := do("GET", "/api/v1/marketplace/listings?category=chat", nil, 200)
	if !strings.Contains(string(chat), "slack-incident-feed") {
		t.Fatalf("chat category should include slack, got: %s", chat)
	}

	// 3. Install without config → pending_config.
	out := do("POST", "/api/v1/marketplace/installs", map[string]any{
		"listing_slug": "slack-incident-feed",
		"label":        "test-soc-channel",
	}, 201)
	var install struct {
		InstallID     string `json:"install_id"`
		IntegrationID string `json:"integration_id"`
		State         string `json:"state"`
	}
	_ = json.Unmarshal(out, &install)
	if install.State != "pending_config" {
		t.Fatalf("expected pending_config, got %s", install.State)
	}
	if install.InstallID == "" || install.IntegrationID == "" {
		t.Fatalf("missing ids: %s", out)
	}

	// 4. Configure → flips to active + integrations.enabled=true.
	do("PATCH", "/api/v1/marketplace/installs/"+install.InstallID,
		map[string]any{"config": map[string]any{
			"url": "https://hooks.slack.example/T0001/B0001/xxxxxxxxx",
		}}, 200)

	// Verify integrations row really got the config + enabled.
	var enabled bool
	_ = h.pool.QueryRow(t.Context(),
		`SELECT enabled FROM integrations WHERE id = $1::uuid`,
		install.IntegrationID).Scan(&enabled)
	if !enabled {
		t.Fatalf("integrations row not enabled after configure")
	}

	// 5. List installs.
	listed := do("GET", "/api/v1/marketplace/installs", nil, 200)
	if !strings.Contains(string(listed), "slack-incident-feed") {
		t.Fatalf("install listing missing slug: %s", listed)
	}

	// 6. Uninstall → suspended + integrations.enabled=false.
	do("DELETE", "/api/v1/marketplace/installs/"+install.InstallID, nil, 200)
	_ = h.pool.QueryRow(t.Context(),
		`SELECT enabled FROM integrations WHERE id = $1::uuid`,
		install.IntegrationID).Scan(&enabled)
	if enabled {
		t.Fatalf("integrations row still enabled after uninstall")
	}

	// 7. Install with config in one shot → active immediately.
	out = do("POST", "/api/v1/marketplace/installs", map[string]any{
		"listing_slug": "pagerduty-critical-alerts",
		"config":       map[string]any{"routing_key": "TEST-KEY"},
	}, 201)
	_ = json.Unmarshal(out, &install)
	if install.State != "active" {
		t.Fatalf("install-with-config should be active, got %s", install.State)
	}
}
