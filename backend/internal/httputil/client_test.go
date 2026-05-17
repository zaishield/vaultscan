package httputil

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Verifies the client respects timeouts AND reuses pooled connections.
// The production behaviour that matters most: under load, are we
// burning ephemeral ports per call? If we are, the transport is
// misconfigured.

func TestNewClient_HonoursTimeout(t *testing.T) {
	t.Parallel()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer slow.Close()
	c := NewClient(Options{Timeout: 100 * time.Millisecond})
	start := time.Now()
	resp, err := c.Get(slow.URL)
	elapsed := time.Since(start)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected timeout error")
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("client waited %s; Timeout=100ms didn't fire", elapsed)
	}
}

func TestNewClient_ReusesConnections(t *testing.T) {
	t.Parallel()
	// Count unique remote addrs (= unique source TCP sessions).
	seen := map[string]struct{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.RemoteAddr] = struct{}{}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := NewClient(Options{})
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// Under a default pool we should see ≤ a couple of source
	// sockets. If we saw 5 (one per request), the keep-alive path
	// is broken.
	if len(seen) > 2 {
		t.Errorf("saw %d unique TCP sessions for 5 calls; pool not reusing", len(seen))
	}
}

func TestNewClient_WrapTransportApplied(t *testing.T) {
	t.Parallel()
	called := 0
	c := NewClient(Options{
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			return &recordingRT{inner: rt, hits: &called}
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if called != 1 {
		t.Errorf("WrapTransport hits=%d want 1", called)
	}
}

func TestNewClient_RejectsOversizedResponseHeaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Emit a 256 KB single header — past our 64 KB cap.
		w.Header().Set("X-Boom", strings.Repeat("a", 256*1024))
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := NewClient(Options{})
	resp, err := c.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected MaxResponseHeaderBytes to reject the overlarge header")
	}
}

type recordingRT struct {
	inner http.RoundTripper
	hits  *int
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.hits++
	return r.inner.RoundTrip(req)
}
