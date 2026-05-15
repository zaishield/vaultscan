//go:build integration

package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// capturedHTTP is a tiny test helper: spins an httptest server that
// invokes `onBody` with the raw POST body, replies 202 Accepted. Used
// to inspect what a transport / adapter actually sent without
// reaching real third-party APIs.
type capturedHTTP struct {
	server *httptest.Server
	client *http.Client
}

func newCapturedHTTP(t *testing.T, onBody func(body []byte)) *capturedHTTP {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		onBody(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"ok","dedup_key":"captured"}`))
	}))
	return &capturedHTTP{
		server: srv,
		// Force every request through the test server regardless of
		// the URL the transport thinks it's calling. Wrap the
		// transport in a small redirector.
		client: &http.Client{
			Transport: &redirectingTransport{target: srv.URL},
		},
	}
}

func (c *capturedHTTP) close() { c.server.Close() }

type redirectingTransport struct {
	target string
}

func (r *redirectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the URL to point at our test server while keeping the
	// path so the handler matches.
	newURL, _ := req.URL.Parse(r.target)
	req.URL.Scheme = newURL.Scheme
	req.URL.Host = newURL.Host
	return http.DefaultTransport.RoundTrip(req)
}
