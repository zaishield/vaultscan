package uploader

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUploader_Success(t *testing.T) {
	mu := sync.Mutex{}
	var captured struct {
		body, agentID, fp, tool, hmac, fmt string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body, _ := io.ReadAll(r.Body)
		captured.body = string(body)
		captured.agentID = r.Header.Get("X-Agent-Id")
		captured.fp = r.Header.Get("X-Agent-Cert-Fingerprint")
		captured.tool = r.URL.Query().Get("tool")
		captured.hmac = r.Header.Get("X-Vaultscan-Envelope-HMAC")
		captured.fmt = r.Header.Get("X-Vaultscan-Envelope-Format")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u := New()
	jobID := uuid.New()
	agentID := uuid.New()
	err := u.UploadResult(context.Background(), srv.Client(), srv.URL,
		jobID, "nmap", []byte("PORT 22/tcp open ssh"), agentID, "abc123fp", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(captured.body, "open ssh") {
		t.Errorf("body not forwarded: %q", captured.body)
	}
	if captured.tool != "nmap" || captured.agentID != agentID.String() || captured.fp != "abc123fp" {
		t.Errorf("required headers missing: %+v", captured)
	}
	if captured.hmac != "deadbeef" {
		t.Errorf("HMAC header not propagated: %q", captured.hmac)
	}
	if captured.fmt != "tar.gz/v1" {
		t.Errorf("envelope-format header missing: %q", captured.fmt)
	}
}

// 5xx → should retry. We return 503 twice then 200; expect attempts==3.
func TestUploader_Retries5xx(t *testing.T) {
	t.Parallel()
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	u := &Uploader{MaxAttempts: 5, BaseBackoff: 10 * time.Millisecond}
	if err := u.UploadResult(context.Background(), srv.Client(), srv.URL,
		uuid.New(), "x", []byte("y"), uuid.New(), "fp", ""); err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("got %d attempts, want 3", got)
	}
}

// 400 Bad Request → should NOT retry (terminal client error).
func TestUploader_BadRequestNotRetried(t *testing.T) {
	t.Parallel()
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(400)
	}))
	defer srv.Close()
	u := &Uploader{MaxAttempts: 5, BaseBackoff: 10 * time.Millisecond}
	err := u.UploadResult(context.Background(), srv.Client(), srv.URL,
		uuid.New(), "x", []byte("y"), uuid.New(), "fp", "")
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("got %d attempts, want 1 (no retry on 400)", got)
	}
}

// 429 Too Many Requests → should retry.
func TestUploader_429IsRetried(t *testing.T) {
	t.Parallel()
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 2 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	u := &Uploader{MaxAttempts: 3, BaseBackoff: 10 * time.Millisecond}
	if err := u.UploadResult(context.Background(), srv.Client(), srv.URL,
		uuid.New(), "x", []byte("y"), uuid.New(), "fp", ""); err != nil {
		t.Fatalf("expected eventual success after 429, got %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("got %d attempts, want 2", got)
	}
}

// Context cancel during backoff → return ctx.Err quickly.
func TestUploader_CtxCancelDuringBackoff(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	u := &Uploader{MaxAttempts: 5, BaseBackoff: 1 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := u.UploadResult(ctx, srv.Client(), srv.URL,
		uuid.New(), "x", []byte("y"), uuid.New(), "fp", "")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected ctx-cancel error")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("client kept retrying past ctx cancel: %s", elapsed)
	}
}
