//go:build integration

// §33 Customer feedback API.

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSection33_SubmitListTriageFeedback(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	tenantID, _ := h.makeTenant(t, "fb-tenant")
	tok := mintToken(t, tenantID)

	post := func(path string, body any, want int) []byte {
		t.Helper()
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(body)
		req, _ := http.NewRequest("POST", srv.URL+path, &buf)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Tenant-Id", tenantID.String())
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s: want %d got %d body=%s", path, want, resp.StatusCode, out)
		}
		return out
	}

	// Submit a bug report.
	bug := post("/api/v1/feedback", map[string]any{
		"category": "bug",
		"severity": "high",
		"title":    "Findings list pagination broken",
		"body":     "Clicking page 2 returns the same rows.",
		"feature":  "/findings",
		"portal_url": "https://portal/findings?page=2",
	}, 201)
	if !strings.Contains(string(bug), `"id"`) {
		t.Fatalf("response missing id: %s", bug)
	}

	// Submit an NPS rating.
	rating := 9
	npsBody := map[string]any{
		"category": "nps",
		"rating":   rating,
		"title":    "NPS",
		"body":     "Great platform.",
	}
	post("/api/v1/feedback", npsBody, 201)

	// NPS without rating rejected.
	bad := map[string]any{
		"category": "nps", "title": "NPS", "body": "no rating",
	}
	post("/api/v1/feedback", bad, 400)

	// Unknown category rejected.
	post("/api/v1/feedback", map[string]any{
		"category": "rant", "title": "x", "body": "y",
	}, 400)

	// Dismiss NPS prompt for the next cooldown window.
	post("/api/v1/feedback/dismiss-nps", nil, 200)

	// Admin lists new feedback.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/feedback?status=new", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Tenant-Id", tenantID.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("list %d: %s", resp.StatusCode, body)
	}
	var listed struct {
		Items []struct {
			ID       string `json:"id"`
			Category string `json:"category"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &listed)
	if len(listed.Items) < 2 {
		t.Fatalf("expected >= 2 new feedback items, got %d", len(listed.Items))
	}
	// urgent/high should be first.
	if listed.Items[0].Severity != "high" {
		t.Fatalf("ordering wrong — bug (high) should come first, got %s",
			listed.Items[0].Severity)
	}

	// Triage one row to resolved.
	first := listed.Items[0].ID
	req2, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/feedback/"+first,
		strings.NewReader(`{"status":"resolved","resolution":"fixed in #1234"}`))
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("X-Tenant-Id", tenantID.String())
	req2.Header.Set("Content-Type", "application/json")
	r2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != 200 {
		body2, _ := io.ReadAll(r2.Body)
		t.Fatalf("triage: %d %s", r2.StatusCode, body2)
	}
}
