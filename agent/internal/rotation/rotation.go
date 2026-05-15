// Package rotation runs the agent's certificate-rotation loop. When the
// stored client cert is within RotateBefore of expiry, the agent
// generates a fresh keypair, builds a PKCS#10 CSR, submits it to
// /api/v1/agents/{id}/csr, and atomically swaps the on-disk cert/key.
//
// Blueprint §28.3 (cert rotation). The cloud-side mint is in
// backend/internal/agents/ops.go::SubmitCSR.
package rotation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Rotator runs the rotation loop. Construct one per agent and call Run.
type Rotator struct {
	client       *http.Client
	gateway      string
	agentID      uuid.UUID
	dataDir      string

	// RotateBefore: rotate when (NotAfter - now) <= this.
	RotateBefore time.Duration
	// CheckEvery: how often to recheck the cert expiry.
	CheckEvery   time.Duration

	mu          sync.RWMutex
	fingerprint string // updated atomically on a successful rotation
}

func New(client *http.Client, gateway string, agentID uuid.UUID, dataDir, fingerprint string) *Rotator {
	return &Rotator{
		client: client, gateway: gateway, agentID: agentID, dataDir: dataDir,
		RotateBefore: 30 * 24 * time.Hour,
		CheckEvery:   12 * time.Hour,
		fingerprint:  fingerprint,
	}
}

// Fingerprint returns the most recent installed cert fingerprint. Safe
// for concurrent readers; updated under lock on each successful rotation.
func (r *Rotator) Fingerprint() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fingerprint
}

// Run is the loop. Returns when ctx is cancelled.
func (r *Rotator) Run(ctx context.Context, onRotated func(newFingerprint string)) {
	t := time.NewTicker(r.CheckEvery)
	defer t.Stop()
	// First check on boot, after a small jitter delay.
	select {
	case <-time.After(10 * time.Second):
	case <-ctx.Done():
		return
	}
	for {
		if err := r.maybeRotate(ctx); err != nil {
			// Soft fail; we'll retry next tick.
			_ = err
		} else if onRotated != nil {
			onRotated(r.Fingerprint())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// maybeRotate returns nil if no rotation was needed OR a rotation
// succeeded. Returns the underlying error otherwise.
func (r *Rotator) maybeRotate(ctx context.Context) error {
	due, err := r.dueForRotation()
	if err != nil {
		return err
	}
	if !due {
		return nil
	}
	return r.rotateOnce(ctx)
}

func (r *Rotator) dueForRotation() (bool, error) {
	pemBytes, err := os.ReadFile(filepath.Join(r.dataDir, "agent.crt"))
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false, errors.New("rotation: agent.crt not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	return time.Until(cert.NotAfter) <= r.RotateBefore, nil
}

// rotateOnce: generate a key, build a CSR, send it, write the cert.
func (r *Rotator) rotateOnce(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rotation: gen key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "vaultscan-agent-" + r.agentID.String(),
			Organization: []string{"ZAISHIELD VAULTSCAN"},
		},
	}, key)
	if err != nil {
		return fmt.Errorf("rotation: build CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	url := r.gateway + "/api/v1/agents/" + r.agentID.String() + "/csr"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Id", r.agentID.String())
	req.Header.Set("X-Agent-Cert-Fingerprint", r.Fingerprint())
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("rotation: gateway %d: %s", resp.StatusCode, respBody)
	}
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
		Fingerprint    string `json:"fingerprint"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("rotation: decode reply: %w", err)
	}
	if out.CertificatePEM == "" || out.Fingerprint == "" {
		return errors.New("rotation: empty cert in reply")
	}
	// Cross-check the fingerprint locally before trusting the response.
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	if block == nil {
		return errors.New("rotation: reply cert not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != out.Fingerprint {
		return errors.New("rotation: server-reported fingerprint != hash of returned cert")
	}

	return r.atomicSwap(out.CertificatePEM, key, out.Fingerprint)
}

// atomicSwap writes the new cert + key + fingerprint to staging files
// then renames them over the live ones. POSIX rename is atomic, so we
// never leave an inconsistent (new cert, old key) pair on disk.
func (r *Rotator) atomicSwap(certPEM string, key *rsa.PrivateKey, fingerprint string) error {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	stage := func(name string, data []byte) (string, error) {
		p := filepath.Join(r.dataDir, name+".next")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return "", err
		}
		return p, nil
	}
	certNext, err := stage("agent.crt", []byte(certPEM))
	if err != nil {
		return err
	}
	keyNext, err := stage("agent.key", keyPEM)
	if err != nil {
		_ = os.Remove(certNext)
		return err
	}
	fpNext, err := stage("fingerprint", []byte(fingerprint))
	if err != nil {
		_ = os.Remove(certNext)
		_ = os.Remove(keyNext)
		return err
	}
	for _, f := range []struct{ from, to string }{
		{certNext, filepath.Join(r.dataDir, "agent.crt")},
		{keyNext, filepath.Join(r.dataDir, "agent.key")},
		{fpNext, filepath.Join(r.dataDir, "fingerprint")},
	} {
		if err := os.Rename(f.from, f.to); err != nil {
			return fmt.Errorf("rotation: rename %s: %w", f.to, err)
		}
	}
	r.mu.Lock()
	r.fingerprint = fingerprint
	r.mu.Unlock()
	return nil
}
