// Package verifier validates RSA-signed scan jobs the cloud sends to the
// agent (Blueprint §11.3, §13.5).
//
// Trust bootstrap, in order:
//
//   1. /etc/vaultscan-agent/cloud-public.pem — preferred. Operators
//      distribute this via configuration management before the agent ever
//      contacts the cloud.
//   2. $VAULTSCAN_CLOUD_PUBLIC_KEY — path or PEM literal supplied at
//      install time.
//   3. <data-dir>/cloud-public.pem — cached after first FetchAndPersist
//      from the API. The agent will use this on subsequent runs.
//
// In all cases a successful Verify requires a non-empty signature AND a
// loaded key. Production deployments MUST distribute the key out-of-band;
// the FetchAndPersist path is a convenience for first-boot bootstrap.
package verifier

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Verifier struct {
	mu  sync.RWMutex
	pub *rsa.PublicKey
}

// New loads a key from disk / env. Returns a Verifier even when no key was
// found; the agent can later call FetchAndPersist to populate it from the
// API. Verify() refuses to validate anything until a key is loaded.
func New() *Verifier {
	v := &Verifier{}
	for _, src := range []string{
		"/etc/vaultscan-agent/cloud-public.pem",
		os.Getenv("VAULTSCAN_CLOUD_PUBLIC_KEY"),
	} {
		if src == "" {
			continue
		}
		// Env var may carry an inline PEM literal as well as a path.
		if strings.Contains(src, "-----BEGIN") {
			v.tryLoad([]byte(src))
			continue
		}
		if pemBytes, err := os.ReadFile(src); err == nil {
			v.tryLoad(pemBytes)
		}
	}
	return v
}

// Loaded reports whether a public key is available for verification.
func (v *Verifier) Loaded() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.pub != nil
}

// PublicKey returns the loaded key for callers that need to verify
// signatures of their own (the updater, for example, signs manifests
// with the same key the job verifier uses).
func (v *Verifier) PublicKey() *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.pub
}

// FetchAndPersist fetches the orchestrator's RSA public key from the API and
// caches it under <dataDir>/cloud-public.pem. Subsequent runs load it from
// New() once the file exists at that path (the caller is responsible for
// pointing /etc/.../cloud-public.pem at the cached file).
//
// Operators should override the bootstrap source in production; this method
// exists so a single-tenant or air-gapped pilot can come up without a
// pre-distributed PEM.
func (v *Verifier) FetchAndPersist(ctx context.Context, apiBaseURL, dataDir string) error {
	if apiBaseURL == "" {
		return errors.New("verifier: API URL required for first-boot fetch")
	}
	url := strings.TrimRight(apiBaseURL, "/") + "/api/v1/orchestrator/public-key"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("verifier: API returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return err
	}
	if !v.tryLoad(body) {
		return errors.New("verifier: API response is not a valid PEM RSA public key")
	}
	if dataDir != "" {
		_ = os.MkdirAll(dataDir, 0o700)
		_ = os.WriteFile(filepath.Join(dataDir, "cloud-public.pem"), body, 0o600)
	}
	return nil
}

// Verify decodes sigB64 and validates that it's a valid PKCS1v15 RSA
// signature over sha256(manifest). Returns a hard error when no key is
// loaded — the agent treats this as "refuse the job".
func (v *Verifier) Verify(manifest []byte, sigB64, _ string) error {
	v.mu.RLock()
	pub := v.pub
	v.mu.RUnlock()
	if pub == nil {
		return errors.New("verifier: no cloud public key loaded; refusing to verify")
	}
	if sigB64 == "" {
		return errors.New("verifier: signature missing")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(manifest)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// tryLoad parses pemBytes and, on success, swaps it in as the active key.
func (v *Verifier) tryLoad(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false
	}
	v.mu.Lock()
	v.pub = rsaPub
	v.mu.Unlock()
	return true
}
