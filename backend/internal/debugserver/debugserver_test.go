package debugserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pprof on a production network is a profiling-data goldmine. The
// debug server MUST refuse unauthenticated calls when a token is set,
// MUST accept the correct token, and MUST do the comparison in
// constant time so a remote attacker can't probe the secret one byte
// at a time.

func TestDebugServer_RejectsMissingToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(New("", "secret-token-32-bytes-aaaaaaaaaaaaaaaaaaaaaa").Handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate=%q must advertise Bearer challenge", got)
	}
}

func TestDebugServer_RejectsWrongToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(New("", "real-token-32-bytes-aaaaaaaaaaaaaaaaaaaaaaaa").Handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/debug/pprof/heap", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d want 401", resp.StatusCode)
	}
}

func TestDebugServer_AcceptsCorrectToken(t *testing.T) {
	t.Parallel()
	token := "valid-token-32-bytes-aaaaaaaaaaaaaaaaaaaaaaaa"
	srv := httptest.NewServer(New("", token).Handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/debug/pprof/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("got %d want 200 body=%s", resp.StatusCode, body)
	}
}

func TestDebugServer_HealthzAlwaysOpen(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(New("", "any-token-here-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Handler)
	defer srv.Close()

	// Liveness probe is intentionally open so an operator's curl can
	// confirm the debug server is up without provisioning credentials.
	resp, err := http.Get(srv.URL + "/debug/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/debug/healthz = %d want 200", resp.StatusCode)
	}
}

func TestDebugServer_NoTokenInDevMode(t *testing.T) {
	t.Parallel()
	// Empty tokenSecret = dev: pprof is open to anyone who can reach
	// the bound addr. The production guard refuses to start with
	// DebugAddr set + token empty, so this path is dev-only.
	srv := httptest.NewServer(New("", "").Handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d want 200 (dev mode)", resp.StatusCode)
	}
}
