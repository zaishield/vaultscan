package secrets

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newInfisicalStub(t *testing.T, store map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/secrets/raw/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer good-token") {
			http.Error(w, "forbidden", 403)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
		// On POST, path is in JSON body; on GET, in query.
		var path string
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			var bin struct {
				SecretPath string `json:"secretPath"`
			}
			_ = json.Unmarshal(body, &bin)
			path = bin.SecretPath
		} else {
			path = r.URL.Query().Get("secretPath")
		}
		fullKey := path + "/" + key
		fullKey = strings.ReplaceAll(fullKey, "//", "/")
		t.Logf("stub: %s key=%q path=%q full=%q", r.Method, key, path, fullKey)

		switch r.Method {
		case http.MethodGet:
			v, ok := store[fullKey]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			body, _ := json.Marshal(map[string]any{
				"secret": map[string]any{
					"secretKey":   key,
					"secretValue": v,
				},
			})
			w.Write(body)
		case http.MethodPost:
			var in struct {
				SecretValue string `json:"secretValue"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			store[fullKey] = in.SecretValue
			w.WriteHeader(204)
		}
	})
	return httptest.NewServer(mux)
}

func TestInfisicalBackend_RoundTrip(t *testing.T) {
	store := map[string]string{}
	srv := newInfisicalStub(t, store)
	defer srv.Close()
	b, err := NewInfisicalBackend(InfisicalConfig{
		Addr: srv.URL, ProjectID: "p1", Environment: "prod", Token: "good-token",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := "integrations/pagerduty/routing-key"
	if err := b.Put(context.Background(), ref, "PD-XYZ"); err != nil {
		t.Fatal(err)
	}
	v, err := b.Get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if v != "PD-XYZ" {
		t.Errorf("got %q want PD-XYZ", v)
	}
}

func TestInfisicalBackend_NotFound(t *testing.T) {
	srv := newInfisicalStub(t, map[string]string{})
	defer srv.Close()
	b, _ := NewInfisicalBackend(InfisicalConfig{
		Addr: srv.URL, ProjectID: "p", Environment: "prod", Token: "good-token",
		HTTPClient: srv.Client(),
	})
	if _, err := b.Get(context.Background(), "missing/key"); err == nil {
		t.Error("expected not-found")
	}
}

func TestInfisicalBackend_AuthFailure(t *testing.T) {
	srv := newInfisicalStub(t, map[string]string{"a/b": "v"})
	defer srv.Close()
	b, _ := NewInfisicalBackend(InfisicalConfig{
		Addr: srv.URL, ProjectID: "p", Environment: "prod", Token: "wrong-token",
		HTTPClient: srv.Client(),
	})
	if _, err := b.Get(context.Background(), "a/b"); err == nil {
		t.Error("expected auth failure")
	}
}

func TestInfisicalBackend_RejectsBadConfig(t *testing.T) {
	if _, err := NewInfisicalBackend(InfisicalConfig{}); err == nil {
		t.Error("empty config should error")
	}
}

func TestFactory_DispatchesByName(t *testing.T) {
	cases := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"env", "env", false},
		{"memory", "memory", false},
		{"unknown", "tarot-cards", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewBackendFromConfig(FactoryConfig{Backend: c.backend})
			if (err != nil) != c.wantErr {
				t.Errorf("backend=%s: err=%v, wantErr=%v", c.backend, err, c.wantErr)
			}
		})
	}
}
