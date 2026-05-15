package uploader

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestUploader_Success(t *testing.T) {
	mu := sync.Mutex{}
	var captured struct {
		body, agentID, fp, tool string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body, _ := io.ReadAll(r.Body)
		captured.body = string(body)
		captured.agentID = r.Header.Get("X-Agent-Id")
		captured.fp = r.Header.Get("X-Agent-Cert-Fingerprint")
		captured.tool = r.URL.Query().Get("tool")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u := New()
	jobID := uuid.New()
	agentID := uuid.New()
	err := u.UploadResult(context.Background(), srv.Client(), srv.URL,
		jobID, "nmap", []byte("PORT 22/tcp open ssh"), agentID, "abc123fp")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(captured.body, "open ssh") {
		t.Errorf("body not forwarded: %q", captured.body)
	}
	if captured.tool != "nmap" {
		t.Errorf("tool query not set: %q", captured.tool)
	}
	if captured.agentID != agentID.String() {
		t.Errorf("X-Agent-Id mismatch")
	}
	if captured.fp != "abc123fp" {
		t.Errorf("X-Agent-Cert-Fingerprint mismatch")
	}
}

func TestUploader_GatewayError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	u := New()
	err := u.UploadResult(context.Background(), srv.Client(), srv.URL,
		uuid.New(), "x", []byte("y"), uuid.New(), "fp")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("expected 503 error, got %v", err)
	}
}
