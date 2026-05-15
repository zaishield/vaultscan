package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// stubListener records whether emergency.Trigger was called.
type stubListener struct{ triggered atomic.Bool }

func (s *stubListener) Trigger() { s.triggered.Store(true) }

func TestTick_SendsRichTelemetry(t *testing.T) {
	var captured map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	counters := &Counters{}
	counters.BumpRunning(2)
	counters.BumpImagePullsFailed()

	tick(context.Background(), srv.Client(), zerolog.Nop(), Config{
		Gateway: srv.URL, AgentID: uuid.New(),
		Fingerprint:    func() string { return "test-fp" },
		ScannerVersion: "1.2.3",
		Counters:       counters,
	})

	wantFields := []string{
		"cpu_percent", "memory_percent", "running_jobs",
		"image_pulls_failed", "version", "kernel_version", "payload",
	}
	for _, f := range wantFields {
		if _, ok := captured[f]; !ok {
			t.Fatalf("heartbeat payload missing %q: %+v", f, captured)
		}
	}
	if captured["version"] != "1.2.3" {
		t.Fatalf("version mismatch: %v", captured["version"])
	}
	if rj, _ := captured["running_jobs"].(float64); rj != 2 {
		t.Fatalf("running_jobs not threaded through counters: %v", captured["running_jobs"])
	}
}

func TestTick_AcksEmergencyStop(t *testing.T) {
	stopID := uuid.New()
	var acked atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		// Reply with a pending emergency stop.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"latest_emergency_stop": map[string]any{
				"id":     stopID,
				"ack_ts": nil,
			},
		})
	})
	mux.HandleFunc("/api/v1/emergency-stops/"+stopID.String()+"/ack", func(w http.ResponseWriter, r *http.Request) {
		acked.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	listener := &stubListener{}
	tick(context.Background(), srv.Client(), zerolog.Nop(), Config{
		Gateway: srv.URL, AgentID: uuid.New(),
		Fingerprint:    func() string { return "test-fp" },
		ScannerVersion: "1.0.0",
		Counters:       &Counters{},
		Emergency:      listener,
	})
	if !acked.Load() {
		t.Fatal("heartbeat must ack a pending emergency stop")
	}
	if !listener.triggered.Load() {
		t.Fatal("heartbeat must Trigger() the local emergency listener")
	}
}

func TestTick_DoesNotAckResolvedStop(t *testing.T) {
	var ackEndpointHit atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		ack := "2026-01-01T00:00:00Z"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"latest_emergency_stop": map[string]any{
				"id":     uuid.New(),
				"ack_ts": &ack,
			},
		})
	})
	mux.HandleFunc("/api/v1/emergency-stops/", func(w http.ResponseWriter, r *http.Request) {
		ackEndpointHit.Store(true)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tick(context.Background(), srv.Client(), zerolog.Nop(), Config{
		Gateway: srv.URL, AgentID: uuid.New(),
		Fingerprint: func() string { return "x" },
		Counters:    &Counters{},
		Emergency:   &stubListener{},
	})
	if ackEndpointHit.Load() {
		t.Fatal("agent must not re-ack an already-acked stop")
	}
}
