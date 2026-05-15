// Package heartbeat ticks a small JSON status payload to the agent gateway.
package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func Run(ctx context.Context, log zerolog.Logger, gateway string, agentID uuid.UUID, fp string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send(ctx, client, gateway, agentID, fp, log)
		}
	}
}

func send(ctx context.Context, client *http.Client, gateway string, agentID uuid.UUID, fp string, log zerolog.Logger) {
	mem := runtime.MemStats{}
	runtime.ReadMemStats(&mem)
	body, _ := json.Marshal(map[string]any{
		"cpu_percent":    0.0,
		"memory_percent": float64(mem.Alloc) / float64(mem.Sys+1) * 100,
		"running_jobs":   0,
		"queue_depth":    0,
		"version":        "1.0.0",
		"payload":        map[string]any{"go": runtime.Version()},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway+"/api/v1/agents/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("X-Agent-Id", agentID.String())
	req.Header.Set("X-Agent-Cert-Fingerprint", fp)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("heartbeat")
		return
	}
	resp.Body.Close()
}
