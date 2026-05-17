//go:build integration

// Idempotency-Key middleware. Standard REST safe-retry semantics:
//   1. Same key + same body → replay cached response (Idempotent-Replay: true)
//   2. Same key + different body → 409 conflict
//   3. No key → no protection (pass-through)
//
// We test against the real handler stack so we exercise the
// captureWriter + DB round-trip end-to-end.

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIdempotency_ReplaysSameKeyAndBody(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	_, _ = h.makeTenant(t, "idem-replay-"+uuid.NewString()[:6])

	tok := mintToken(t, uuid.New()) // super_admin via mintToken
	key := uuid.NewString()
	body := []byte(`{"name":"contract-idem","slug":"contract-idem-` +
		uuid.NewString()[:6] + `","partner_id":"00000000-0000-0000-0000-0000000000b1"}`)

	send := func() (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/tenants",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf, _ := io.ReadAll(resp.Body)
		return resp, buf
	}

	resp1, body1 := send()
	if resp1.StatusCode != 201 {
		t.Fatalf("first request: status=%d body=%s", resp1.StatusCode, body1)
	}
	if got := resp1.Header.Get("Idempotent-Replay"); got != "" {
		t.Errorf("first request should NOT carry Idempotent-Replay; got %q", got)
	}

	// Same key + same body → replay. Status + body byte-identical.
	resp2, body2 := send()
	if resp2.StatusCode != 201 {
		t.Errorf("replay status=%d want 201 (replayed)", resp2.StatusCode)
	}
	if got := resp2.Header.Get("Idempotent-Replay"); got != "true" {
		t.Errorf("replay missing Idempotent-Replay=true; got %q", got)
	}
	if !bytes.Equal(body1, body2) {
		t.Errorf("replay body differs: first=%q second=%q", body1, body2)
	}
}

func TestIdempotency_RejectsKeyReuseWithDifferentBody(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	_, _ = h.makeTenant(t, "idem-conflict-"+uuid.NewString()[:6])

	tok := mintToken(t, uuid.New())
	key := uuid.NewString()
	send := func(body []byte) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/tenants",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf, _ := io.ReadAll(resp.Body)
		return resp, buf
	}

	body1 := []byte(`{"name":"first","slug":"first-` +
		uuid.NewString()[:6] + `","partner_id":"00000000-0000-0000-0000-0000000000b1"}`)
	if r, _ := send(body1); r.StatusCode != 201 {
		t.Fatalf("first: %d", r.StatusCode)
	}

	body2 := []byte(`{"name":"second","slug":"second-` +
		uuid.NewString()[:6] + `","partner_id":"00000000-0000-0000-0000-0000000000b1"}`)
	r, buf := send(body2)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("same key + different body: status=%d want 409 body=%s", r.StatusCode, buf)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(buf, &envelope)
	if envelope.Error.Code != "idempotency_conflict" {
		t.Errorf("error code=%q want idempotency_conflict", envelope.Error.Code)
	}
}

func TestIdempotency_NoKeyMeansNoProtection(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	_, _ = h.makeTenant(t, "idem-nokey-"+uuid.NewString()[:6])

	tok := mintToken(t, uuid.New())
	send := func(slug string) int {
		t.Helper()
		body := []byte(`{"name":"x","slug":"` + slug +
			`","partner_id":"00000000-0000-0000-0000-0000000000b1"}`)
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/tenants",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		// NO Idempotency-Key header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Both calls execute fresh (no replay).
	r1 := send("nokey-1-" + uuid.NewString()[:6])
	r2 := send("nokey-2-" + uuid.NewString()[:6])
	if r1 != 201 || r2 != 201 {
		t.Errorf("no-key calls: %d, %d (both should fire)", r1, r2)
	}
}

func TestIdempotency_RejectsMalformedKey(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	_, _ = h.makeTenant(t, "idem-bad-"+uuid.NewString()[:6])

	tok := mintToken(t, uuid.New())
	for _, badKey := range []string{
		"",        // empty handled by middleware as pass-through, but UUID 12-char check
		"abc",     // too short
		strings.Repeat("a", 200),   // too long
		"with space-here",          // non-printable space inside (printable per ASCII, OK actually) — skip
	} {
		if badKey == "" || badKey == "with space-here" {
			continue
		}
		body := []byte(`{"name":"x","slug":"bad-` + uuid.NewString()[:6] +
			`","partner_id":"00000000-0000-0000-0000-0000000000b1"}`)
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/tenants",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Idempotency-Key", badKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("badKey=%q: status=%d want 400", badKey, resp.StatusCode)
		}
	}
}
