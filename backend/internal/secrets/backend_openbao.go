// backend_openbao.go — OpenBao / HashiCorp Vault KV v2 backend.
//
// OpenBao is the open-source fork of HashiCorp Vault and speaks the
// same REST API. Both work with this backend; the only operational
// difference is the binary you run.
//
// API:
//
//   GET  /v1/<mount>/data/<path>   → {"data":{"data":{...},"metadata":{...}}}
//   POST /v1/<mount>/data/<path>   body {"data":{...}}
//   X-Vault-Token: <token>         (or X-Vault-Namespace for HCP namespaces)
//
// Refs map deterministically:
//   "integrations/jira/api-token" → /v1/<mount>/data/integrations/jira/api-token
//   The value at the secret is interpreted as the field "value" inside
//   the KV v2 data blob (so Get returns data["value"]).
//
// Auth: token-based (matches kubernetes/approle/jwt auth methods that
// also yield a token). Token refresh is the deployer's responsibility
// (sidecar like vault-agent or auto-renew via VAULTSCAN_SECRETS_TOKEN
// being a path to a file with the current token).

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenBaoBackend speaks the KV v2 REST API of OpenBao or HashiCorp Vault.
type OpenBaoBackend struct {
	addr       string  // https://vault.internal:8200
	mount      string  // e.g. "kv" or "secret"
	namespace  string  // optional X-Vault-Namespace header (HCP / Vault Enterprise)
	tokenSrc   tokenSource
	httpClient *http.Client
}

// tokenSource lets the backend transparently re-read the token from
// disk if VAULTSCAN_SECRETS_TOKEN points at a file (typical with
// vault-agent sidecar that periodically rewrites the file).
type tokenSource interface {
	Token() (string, error)
}

type staticToken string

func (s staticToken) Token() (string, error) { return string(s), nil }

type fileToken struct{ path string }

func (f fileToken) Token() (string, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("secrets: read token file %s: %w", f.path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

type OpenBaoConfig struct {
	Addr      string  // required
	Mount     string  // default "kv"
	Namespace string  // optional
	// Token: literal token, OR (if Token starts with "file:") a path
	// like "file:/var/run/secrets/vault/token" — re-read on every
	// secret fetch so vault-agent rotation just works.
	Token      string
	HTTPClient *http.Client
}

func NewOpenBaoBackend(cfg OpenBaoConfig) (*OpenBaoBackend, error) {
	if cfg.Addr == "" {
		return nil, errors.New("secrets: openbao addr required")
	}
	if cfg.Token == "" {
		return nil, errors.New("secrets: openbao token required (literal or file:/path)")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "kv"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	var ts tokenSource
	if strings.HasPrefix(cfg.Token, "file:") {
		ts = fileToken{path: strings.TrimPrefix(cfg.Token, "file:")}
	} else {
		ts = staticToken(cfg.Token)
	}
	return &OpenBaoBackend{
		addr:       strings.TrimRight(cfg.Addr, "/"),
		mount:      mount,
		namespace:  cfg.Namespace,
		tokenSrc:   ts,
		httpClient: hc,
	}, nil
}

func (b *OpenBaoBackend) url(ref string) string {
	return fmt.Sprintf("%s/v1/%s/data/%s", b.addr, b.mount, strings.TrimLeft(ref, "/"))
}

func (b *OpenBaoBackend) headers() (http.Header, error) {
	tok, err := b.tokenSrc.Token()
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set("X-Vault-Token", tok)
	h.Set("Accept", "application/json")
	if b.namespace != "" {
		h.Set("X-Vault-Namespace", b.namespace)
	}
	return h, nil
}

// kvV2Response is what GET /v1/<mount>/data/<path> returns.
type kvV2Response struct {
	Data struct {
		Data     map[string]any `json:"data"`
		Metadata map[string]any `json:"metadata"`
	} `json:"data"`
}

func (b *OpenBaoBackend) Get(ctx context.Context, ref string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url(ref), nil)
	if err != nil {
		return "", err
	}
	hdr, err := b.headers()
	if err != nil {
		return "", err
	}
	req.Header = hdr

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		var r kvV2Response
		if err := json.Unmarshal(body, &r); err != nil {
			return "", fmt.Errorf("secrets: openbao decode: %w", err)
		}
		// Single-string secrets are stored under field "value".
		// Distinguish "value present but wrong type" from "no value
		// field" — the former is an operator misconfig (someone
		// stored a number/bool/object as the value, masking other
		// fields) and should fail loud rather than silently dumping
		// the entire data map.
		if raw, present := r.Data.Data["value"]; present {
			if v, ok := raw.(string); ok {
				return v, nil
			}
			return "", fmt.Errorf("secrets: openbao %q has a 'value' field of type %T (expected string)", ref, raw)
		}
		// Multi-field secrets: serialize the whole data map as JSON
		// so the caller can unmarshal it (cloud creds resolver uses
		// this — KV value is a JSON blob with access_key_id / etc).
		raw, _ := json.Marshal(r.Data.Data)
		return string(raw), nil
	case http.StatusNotFound:
		return "", fmt.Errorf("secrets: ref %q not found in openbao", ref)
	case http.StatusForbidden, http.StatusUnauthorized:
		return "", fmt.Errorf("secrets: openbao auth failed: %d %s", resp.StatusCode, string(body))
	default:
		return "", fmt.Errorf("secrets: openbao %s: %d %s", ref, resp.StatusCode, string(body))
	}
}

func (b *OpenBaoBackend) Put(ctx context.Context, ref, value string) error {
	// Always store as { "data": { "value": <string> } } so Get is
	// symmetric. Multi-field writes go via PutJSON below.
	payload, _ := json.Marshal(map[string]any{
		"data": map[string]any{"value": value},
	})
	return b.put(ctx, ref, payload)
}

// PutJSON stores a multi-field secret. Useful for cloud credentials:
//   secrets.PutJSON(ctx, "cloud/aws/prod", map[string]any{
//     "access_key_id": "...", "secret_access_key": "...",
//   })
func (b *OpenBaoBackend) PutJSON(ctx context.Context, ref string, data map[string]any) error {
	payload, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return err
	}
	return b.put(ctx, ref, payload)
}

func (b *OpenBaoBackend) put(ctx context.Context, ref string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url(ref), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	hdr, err := b.headers()
	if err != nil {
		return err
	}
	req.Header = hdr
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("secrets: openbao put %s: %d %s", ref, resp.StatusCode, string(body))
	}
	return nil
}
