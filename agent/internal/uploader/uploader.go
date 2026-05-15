// Package uploader uploads packaged scan output to the agent gateway over
// outbound TLS (Blueprint §13.3 uploader). Uploads are resumable in
// production via the chunked /artifacts endpoint; the dev build uses a
// single PUT.
package uploader

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type Uploader struct{}

func New() *Uploader { return &Uploader{} }

func (Uploader) UploadResult(ctx context.Context, client *http.Client, gateway string,
	jobID uuid.UUID, tool string, body []byte, agentID uuid.UUID, fp string) error {
	url := fmt.Sprintf("%s/api/v1/agents/jobs/%s/results?tool=%s", gateway, jobID, tool)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Agent-Id", agentID.String())
	req.Header.Set("X-Agent-Cert-Fingerprint", fp)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("upload: %d", resp.StatusCode)
	}
	return nil
}
