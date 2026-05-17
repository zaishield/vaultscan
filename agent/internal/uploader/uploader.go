// Package uploader posts a packaged scan-result envelope to the
// agent gateway over outbound TLS (Blueprint §13.3 uploader).
//
// Reliability model:
//   - Up to 5 attempts with exponential backoff (1s, 2s, 4s, 8s, 16s)
//     plus ±50% jitter so a flapping gateway doesn't see N agents
//     retry in lockstep.
//   - Per-attempt context derived from the caller's so a graceful
//     shutdown / emergency-stop preempts in-flight retries.
//   - 4xx responses (except 408 / 425 / 429) are NOT retried — the
//     gateway has rejected the body and a re-send won't help.
//   - 5xx and network errors are retried.
//   - The envelope HMAC (computed by the packager) is sent as
//     X-Vaultscan-Envelope-HMAC. The gateway recomputes and refuses
//     mismatched envelopes — this is how tamper-in-flight is caught.
//
// Chunked upload is not implemented here yet because the gateway
// /artifacts endpoint doesn't accept chunked uploads. The single
// PUT plus retry-with-jitter is the right shape today; once the
// gateway grows a /artifacts/chunk endpoint, a TransferMode option
// can be added without changing this signature.
package uploader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultMaxAttempts = 5
	defaultBaseBackoff = time.Second
)

type Uploader struct {
	MaxAttempts int
	BaseBackoff time.Duration
}

func New() *Uploader {
	return &Uploader{
		MaxAttempts: defaultMaxAttempts,
		BaseBackoff: defaultBaseBackoff,
	}
}

// UploadResult POSTs the envelope to the agent gateway with retry.
// hmacHex is the X-Vaultscan-Envelope-HMAC header value computed by
// the packager — pass "" if the packager has no key wired (the
// gateway will accept but log+flag as unsigned).
func (u *Uploader) UploadResult(ctx context.Context, client *http.Client, gateway string,
	jobID uuid.UUID, tool string, body []byte,
	agentID uuid.UUID, fp string, hmacHex string) error {
	if client == nil {
		return fmt.Errorf("uploader: nil http client")
	}
	maxAttempts := u.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}
	base := u.BaseBackoff
	if base <= 0 {
		base = defaultBaseBackoff
	}
	url := fmt.Sprintf("%s/api/v1/agents/jobs/%s/results?tool=%s",
		strings.TrimRight(gateway, "/"), jobID, tool)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Per-attempt 60s ceiling so a hung gateway doesn't burn
		// the whole retry budget on one socket.
		attemptCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost,
			url, bytes.NewReader(body))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("X-Agent-Id", agentID.String())
		req.Header.Set("X-Agent-Cert-Fingerprint", fp)
		req.Header.Set("Content-Type", "application/gzip")
		req.Header.Set("X-Vaultscan-Envelope-Format", "tar.gz/v1")
		if hmacHex != "" {
			req.Header.Set("X-Vaultscan-Envelope-HMAC", hmacHex)
		}
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode < 400 {
				return nil
			}
			// 4xx (except retryable subset) → don't retry; the
			// gateway has made up its mind.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
				resp.StatusCode != 408 && resp.StatusCode != 425 && resp.StatusCode != 429 {
				return fmt.Errorf("upload: gateway rejected with %d (not retried)", resp.StatusCode)
			}
			lastErr = fmt.Errorf("upload: gateway returned %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if attempt == maxAttempts {
			break
		}
		// Backoff with ±50% jitter.
		nominal := base * time.Duration(1<<uint(attempt-1))
		jitterFactor := 0.5 + rand.Float64() // [0.5, 1.5)
		sleep := time.Duration(float64(nominal) * jitterFactor)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
	return fmt.Errorf("upload: gave up after %d attempts: %w", maxAttempts, lastErr)
}
