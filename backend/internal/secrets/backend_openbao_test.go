package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newOpenBaoStub(t *testing.T, store map[string]map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// /v1/<mount>/data/<path>
		const prefix = "/v1/kv/data/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "not found", 404)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix)

		if r.Header.Get("X-Vault-Token") != "good-token" {
			http.Error(w, "forbidden", 403)
			return
		}

		switch r.Method {
		case http.MethodGet:
			data, ok := store[key]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			body, _ := json.Marshal(map[string]any{
				"data": map[string]any{"data": data},
			})
			w.Write(body)
		case http.MethodPost:
			var in struct {
				Data map[string]any `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			store[key] = in.Data
			w.WriteHeader(204)
		}
	})
	return httptest.NewServer(mux)
}

func TestOpenBaoBackend_GetSimpleValue(t *testing.T) {
	t.Parallel()
	store := map[string]map[string]any{
		"integrations/jira/api-token": {"value": "abc123"},
	}
	srv := newOpenBaoStub(t, store)
	defer srv.Close()

	b, err := NewOpenBaoBackend(OpenBaoConfig{
		Addr: srv.URL, Mount: "kv", Token: "good-token", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := b.Get(context.Background(), "integrations/jira/api-token")
	if err != nil {
		t.Fatal(err)
	}
	if v != "abc123" {
		t.Errorf("got %q, want abc123", v)
	}
}

func TestOpenBaoBackend_GetMultiFieldReturnsJSON(t *testing.T) {
	t.Parallel()
	store := map[string]map[string]any{
		"cloud/aws/prod": {
			"access_key_id":     "AKIA...",
			"secret_access_key": "wJal...",
		},
	}
	srv := newOpenBaoStub(t, store)
	defer srv.Close()

	b, _ := NewOpenBaoBackend(OpenBaoConfig{
		Addr: srv.URL, Mount: "kv", Token: "good-token", HTTPClient: srv.Client(),
	})
	v, _ := b.Get(context.Background(), "cloud/aws/prod")
	var got map[string]string
	if err := json.Unmarshal([]byte(v), &got); err != nil {
		t.Fatalf("expected JSON multi-field result, got %q: %v", v, err)
	}
	if got["access_key_id"] != "AKIA..." {
		t.Errorf("missing access_key_id field: %v", got)
	}
}

func TestOpenBaoBackend_RoundTrip(t *testing.T) {
	t.Parallel()
	store := map[string]map[string]any{}
	srv := newOpenBaoStub(t, store)
	defer srv.Close()

	b, _ := NewOpenBaoBackend(OpenBaoConfig{
		Addr: srv.URL, Mount: "kv", Token: "good-token", HTTPClient: srv.Client(),
	})
	if err := b.Put(context.Background(), "integrations/slack/webhook", "https://hooks.slack/x"); err != nil {
		t.Fatal(err)
	}
	v, _ := b.Get(context.Background(), "integrations/slack/webhook")
	if v != "https://hooks.slack/x" {
		t.Errorf("roundtrip mismatch: got %q", v)
	}
}

func TestOpenBaoBackend_GetNotFound(t *testing.T) {
	t.Parallel()
	srv := newOpenBaoStub(t, map[string]map[string]any{})
	defer srv.Close()
	b, _ := NewOpenBaoBackend(OpenBaoConfig{
		Addr: srv.URL, Mount: "kv", Token: "good-token", HTTPClient: srv.Client(),
	})
	if _, err := b.Get(context.Background(), "nope"); err == nil {
		t.Error("expected not-found error")
	}
}

func TestOpenBaoBackend_AuthFailure(t *testing.T) {
	t.Parallel()
	srv := newOpenBaoStub(t, map[string]map[string]any{})
	defer srv.Close()
	b, _ := NewOpenBaoBackend(OpenBaoConfig{
		Addr: srv.URL, Mount: "kv", Token: "wrong-token", HTTPClient: srv.Client(),
	})
	_, err := b.Get(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("expected auth failure; got %v", err)
	}
}

func TestOpenBaoBackend_FileToken(t *testing.T) {
	t.Parallel()
	// Write a token to a temp file and use the file:/path scheme.
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	_ = os.WriteFile(path, []byte("good-token\n"), 0o600)

	srv := newOpenBaoStub(t, map[string]map[string]any{
		"x": {"value": "v"},
	})
	defer srv.Close()
	b, _ := NewOpenBaoBackend(OpenBaoConfig{
		Addr: srv.URL, Mount: "kv", Token: "file:" + path, HTTPClient: srv.Client(),
	})
	v, err := b.Get(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if v != "v" {
		t.Errorf("got %q", v)
	}

	// Rotate the token in the file → next fetch should re-read.
	_ = os.WriteFile(path, []byte("rotated-token"), 0o600)
	if _, err := b.Get(context.Background(), "x"); err == nil {
		t.Error("expected auth failure after rotating to invalid token")
	}
}

func TestOpenBaoBackend_RejectsBadConfig(t *testing.T) {
	t.Parallel()
	if _, err := NewOpenBaoBackend(OpenBaoConfig{}); err == nil {
		t.Error("empty config should error")
	}
	if _, err := NewOpenBaoBackend(OpenBaoConfig{Addr: "https://x"}); err == nil {
		t.Error("missing token should error")
	}
}

func TestSplitRef(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, path, key string }{
		{"integrations/jira/api-token", "/integrations/jira", "api-token"},
		{"flat", "/", "flat"},
		{"/leading/slash", "/leading", "slash"},
		{"a/b/c/d", "/a/b/c", "d"},
	}
	for _, c := range cases {
		p, k := splitRef(c.in)
		if p != c.path || k != c.key {
			t.Errorf("splitRef(%q) = (%q,%q), want (%q,%q)", c.in, p, k, c.path, c.key)
		}
	}
}
