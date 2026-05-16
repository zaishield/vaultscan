package searchindex

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func newOSStub(t *testing.T) (*Client, *stubHandler, func()) {
	t.Helper()
	h := &stubHandler{
		indices: map[string]bool{},
		docs:    map[string]map[string]any{},
	}
	srv := httptest.NewServer(h)
	c, err := New(Config{URL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c, h, srv.Close
}

type stubHandler struct {
	mu       sync.Mutex
	indices  map[string]bool
	docs     map[string]map[string]any
	clusterStatus string
}

func (h *stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case r.URL.Path == "/_cluster/health":
		status := h.clusterStatus
		if status == "" {
			status = "green"
		}
		body, _ := json.Marshal(map[string]any{"status": status})
		w.Write(body)
	case r.Method == http.MethodHead && r.URL.Path != "/" && !strings.Contains(r.URL.Path, "/_doc/"):
		idx := strings.TrimPrefix(r.URL.Path, "/")
		if h.indices[idx] {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(404)
		}
	case r.Method == http.MethodPut && !strings.Contains(r.URL.Path, "/_doc/"):
		idx := strings.TrimPrefix(r.URL.Path, "/")
		h.indices[idx] = true
		w.WriteHeader(200)
		w.Write([]byte(`{"acknowledged":true}`))
	case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_doc/"):
		// /<index>/_doc/<id>
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/_doc/", 2)
		if len(parts) != 2 {
			w.WriteHeader(400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		h.docs[parts[0]+"/"+parts[1]] = doc
		w.WriteHeader(201)
		w.Write([]byte(`{"_id":"` + parts[1] + `","result":"created"}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_search"):
		idx := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/_search"), "/")
		var hits []SearchHit
		for k, v := range h.docs {
			if strings.HasPrefix(k, idx+"/") {
				id := strings.TrimPrefix(k, idx+"/")
				hits = append(hits, SearchHit{ID: id, Score: 1.0, Source: v})
			}
		}
		body, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": len(hits)},
				"hits":  hits,
			},
		})
		w.Write(body)
	case r.Method == http.MethodPost && r.URL.Path == "/_bulk":
		w.WriteHeader(200)
		w.Write([]byte(`{"errors":false,"items":[]}`))
	default:
		w.WriteHeader(404)
	}
}

func TestClient_Health(t *testing.T) {
	t.Parallel()
	c, _, cleanup := newOSStub(t)
	defer cleanup()
	status, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status != "green" {
		t.Errorf("got %q, want green", status)
	}
}

func TestClient_EnsureIndex_CreatesNewSkipsExisting(t *testing.T) {
	t.Parallel()
	c, h, cleanup := newOSStub(t)
	defer cleanup()
	if err := c.EnsureIndex(context.Background(), "vaultscan-findings",
		FindingsIndexMapping()); err != nil {
		t.Fatal(err)
	}
	if !h.indices["vaultscan-findings"] {
		t.Error("index not created")
	}
	// Re-call → should be a no-op (HEAD returns 200 → skip PUT).
	if err := c.EnsureIndex(context.Background(), "vaultscan-findings",
		FindingsIndexMapping()); err != nil {
		t.Fatal(err)
	}
}

func TestClient_IndexAndSearch(t *testing.T) {
	t.Parallel()
	c, _, cleanup := newOSStub(t)
	defer cleanup()
	doc := map[string]any{"title": "SQL injection in /login", "severity": "high"}
	if err := c.IndexDoc(context.Background(), "vaultscan-findings", "abc-123",
		doc, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	r, err := c.Search(context.Background(), "vaultscan-findings", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 1 || len(r.Hits) != 1 {
		t.Errorf("expected 1 hit, got total=%d hits=%d", r.Total, len(r.Hits))
	}
	if r.Hits[0].Source["title"] != "SQL injection in /login" {
		t.Errorf("source mismatch: %v", r.Hits[0].Source)
	}
}

func TestClient_BulkSucceeds(t *testing.T) {
	t.Parallel()
	c, _, cleanup := newOSStub(t)
	defer cleanup()
	ops := []BulkOp{
		{Action: "index", Index: "vaultscan-findings", ID: "1", Doc: map[string]any{"x": 1}},
		{Action: "index", Index: "vaultscan-findings", ID: "2", Doc: map[string]any{"x": 2}},
		{Action: "delete", Index: "vaultscan-findings", ID: "3"},
	}
	if err := c.Bulk(context.Background(), ops); err != nil {
		t.Fatal(err)
	}
}

func TestClient_RejectsEmptyURL(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Error("expected error on empty URL")
	}
}

func TestFindingsIndexMapping_HasRequiredFields(t *testing.T) {
	t.Parallel()
	m := FindingsIndexMapping()
	props := m["mappings"].(map[string]any)["properties"].(map[string]any)
	for _, want := range []string{"tenant_id", "title", "severity", "scanner"} {
		if _, ok := props[want]; !ok {
			t.Errorf("mapping missing field: %s", want)
		}
	}
}
