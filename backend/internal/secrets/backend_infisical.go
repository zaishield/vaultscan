// backend_infisical.go — Infisical secrets backend.
//
// Infisical's REST API for raw secret retrieval:
//
//   GET /api/v3/secrets/raw/<key>?
//          workspaceId=<projectId>&environment=<env>&secretPath=<path>
//   Authorization: Bearer <serviceToken>  OR
//   Authorization: <serviceToken>  (Infisical accepts both)
//
// Refs map to:
//   "integrations/jira/api-token" → secretPath=/integrations/jira,
//                                  key=api-token
//
// Project ID + environment are baked into the backend; only path/key
// vary per fetch.

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type InfisicalBackend struct {
	addr        string  // https://app.infisical.com (or self-hosted)
	projectID   string
	environment string  // dev | staging | prod
	token       string
	httpClient  *http.Client
}

type InfisicalConfig struct {
	Addr        string  // default https://app.infisical.com
	ProjectID   string  // required
	Environment string  // required (dev | staging | prod)
	Token       string  // required (service token)
	HTTPClient  *http.Client
}

func NewInfisicalBackend(cfg InfisicalConfig) (*InfisicalBackend, error) {
	if cfg.ProjectID == "" {
		return nil, errors.New("secrets: infisical project_id required")
	}
	if cfg.Environment == "" {
		return nil, errors.New("secrets: infisical environment required")
	}
	if cfg.Token == "" {
		return nil, errors.New("secrets: infisical token required")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = "https://app.infisical.com"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &InfisicalBackend{
		addr:        strings.TrimRight(addr, "/"),
		projectID:   cfg.ProjectID,
		environment: cfg.Environment,
		token:       cfg.Token,
		httpClient:  hc,
	}, nil
}

func splitRef(ref string) (path, key string) {
	ref = strings.TrimLeft(ref, "/")
	idx := strings.LastIndex(ref, "/")
	if idx < 0 {
		return "/", ref
	}
	return "/" + ref[:idx], ref[idx+1:]
}

func (b *InfisicalBackend) Get(ctx context.Context, ref string) (string, error) {
	secretPath, key := splitRef(ref)
	q := url.Values{}
	q.Set("workspaceId", b.projectID)
	q.Set("environment", b.environment)
	q.Set("secretPath", secretPath)
	u := fmt.Sprintf("%s/api/v3/secrets/raw/%s?%s", b.addr, url.PathEscape(key), q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Accept", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("secrets: ref %q not found in infisical", ref)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("secrets: infisical %s: %d %s", ref, resp.StatusCode, string(body))
	}

	var r struct {
		Secret struct {
			SecretKey   string `json:"secretKey"`
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("secrets: infisical decode: %w", err)
	}
	return r.Secret.SecretValue, nil
}

func (b *InfisicalBackend) Put(ctx context.Context, ref, value string) error {
	secretPath, key := splitRef(ref)
	payload, _ := json.Marshal(map[string]any{
		"workspaceId":  b.projectID,
		"environment":  b.environment,
		"secretPath":   secretPath,
		"secretValue":  value,
		"type":         "shared",
	})
	u := fmt.Sprintf("%s/api/v3/secrets/raw/%s", b.addr, url.PathEscape(key))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("secrets: infisical put %s: %d %s", ref, resp.StatusCode, string(body))
	}
	return nil
}
