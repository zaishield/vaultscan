package enroll

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRun_HappyPath(t *testing.T) {
	var seenBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &seenBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	id := uuid.New()
	if err := Run(srv.Client(), srv.URL, id, "one-time-token", dir); err != nil {
		t.Fatal(err)
	}
	// Body must include all three fields.
	for _, want := range []string{"token", "cert_pem", "fingerprint"} {
		if _, ok := seenBody[want]; !ok {
			t.Errorf("body missing %q: %+v", want, seenBody)
		}
	}
	if seenBody["token"] != "one-time-token" {
		t.Errorf("token mismatch: %q", seenBody["token"])
	}
	// Files written?
	for _, name := range []string{"agent.crt", "agent.key", "fingerprint"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
			continue
		}
		// 0600 mode (owner-only).
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, perm)
		}
	}
	fp, err := LoadFingerprint(dir)
	if err != nil || len(fp) != 64 {
		t.Errorf("fingerprint round-trip: %q err=%v", fp, err)
	}
}

func TestRun_GatewayError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	err := Run(srv.Client(), srv.URL, uuid.New(), "wrong-token", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}
}

func TestLoadFingerprint_Missing(t *testing.T) {
	if _, err := LoadFingerprint(t.TempDir()); err == nil {
		t.Error("expected error reading missing fingerprint")
	}
}
