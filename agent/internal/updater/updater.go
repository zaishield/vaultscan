// Package updater polls the cloud for signed agent-update bundles and
// installs the one it's offered, refusing any bundle whose manifest
// signature doesn't verify under the cached cloud public key or whose
// bytes don't match the manifest's sha256.
//
// Blueprint §28.4 (signed agent updates). Bundles are emitted by
// backend/internal/agents/ops.go::PublishBundle.
package updater

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Manifest struct {
	TargetVersion  string `json:"target_version"`
	DownloadURL    string `json:"download_url"`
	BundleSHA256   string `json:"bundle_sha256"`
	MinFromVersion string `json:"min_from_version,omitempty"`
	IssuedAt       string `json:"issued_at"`
}

type Offer struct {
	ID           uuid.UUID `json:"id"`
	Manifest     Manifest  `json:"manifest"`
	Signature    string    `json:"signature_b64"`
	SigningKeyID string    `json:"signing_key_id"`
}

type Updater struct {
	client  *http.Client
	gateway string
	agentID uuid.UUID
	dataDir string

	// CurrentVersion is the version the running binary advertises. Bumped
	// after a successful install (cached in updater state until process
	// restart).
	CurrentVersion string

	// CloudPublicKey verifies the manifest signature. Identical to the
	// key the verifier package uses for job-manifest verification.
	CloudPublicKey *rsa.PublicKey

	// CheckEvery: how often to poll for an offer.
	CheckEvery time.Duration

	// OnInstalled is invoked once the new bundle has been verified and
	// extracted into <data-dir>/next. The supervisor (systemd, K8s
	// liveness, etc.) restarts the agent, which then resolves the
	// "next" symlink as its new binary on boot.
	OnInstalled func(target string)
}

func New(client *http.Client, gateway string, agentID uuid.UUID, dataDir string, pub *rsa.PublicKey, currentVersion string) *Updater {
	return &Updater{
		client: client, gateway: gateway, agentID: agentID, dataDir: dataDir,
		CurrentVersion: currentVersion,
		CloudPublicKey: pub,
		CheckEvery:     6 * time.Hour,
	}
}

func (u *Updater) Run(ctx context.Context) {
	t := time.NewTicker(u.CheckEvery)
	defer t.Stop()
	// First check after a small delay so boot doesn't trample on first-run setup.
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return
	}
	for {
		_ = u.checkAndInstall(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// checkAndInstall fetches the latest offer; if one exists and verifies,
// downloads the bundle, checksums it, extracts to staging, calls
// OnInstalled. Anything fishy → return error, no installation.
func (u *Updater) checkAndInstall(ctx context.Context) error {
	offer, err := u.fetchOffer(ctx)
	if err != nil || offer == nil {
		return err
	}
	if u.CloudPublicKey == nil {
		return errors.New("updater: cloud public key not loaded; refusing all bundles")
	}
	manifestJSON, _ := json.Marshal(offer.Manifest)
	if err := verifyManifest(manifestJSON, offer.Signature, u.CloudPublicKey); err != nil {
		return fmt.Errorf("updater: manifest signature rejected: %w", err)
	}
	body, err := u.fetchBundle(ctx, offer.Manifest.DownloadURL)
	if err != nil {
		return fmt.Errorf("updater: download: %w", err)
	}
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	if !strings.EqualFold(hashHex, offer.Manifest.BundleSHA256) {
		return fmt.Errorf("updater: sha256 mismatch — manifest=%s observed=%s",
			offer.Manifest.BundleSHA256, hashHex)
	}
	stagePath, err := u.stageBundle(offer.Manifest.TargetVersion, body)
	if err != nil {
		return err
	}
	u.CurrentVersion = offer.Manifest.TargetVersion
	if u.OnInstalled != nil {
		u.OnInstalled(stagePath)
	}
	return nil
}

func (u *Updater) fetchOffer(ctx context.Context) (*Offer, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/update-offer?current_version=%s",
		u.gateway, u.agentID, u.CurrentVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Id", u.agentID.String())
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("updater: offer %d: %s", resp.StatusCode, body)
	}
	var offer Offer
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, err
	}
	if offer.Manifest.TargetVersion == "" {
		return nil, nil
	}
	return &offer, nil
}

func (u *Updater) fetchBundle(ctx context.Context, downloadURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("updater: download %d", resp.StatusCode)
	}
	// Cap bundle size to avoid eating the disk on a runaway response.
	return io.ReadAll(io.LimitReader(resp.Body, 256*1024*1024))
}

// stageBundle writes the bundle bytes to <data-dir>/updates/<version>.bundle
// and points <data-dir>/next at the same path via a sibling file. The
// supervisor consumes <data-dir>/next on boot.
func (u *Updater) stageBundle(version string, body []byte) (string, error) {
	dir := filepath.Join(u.dataDir, "updates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, version+".bundle")
	tmp := dest + ".part"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	// Write a "next" pointer so the supervisor can find it without
	// listing the directory.
	if err := os.WriteFile(filepath.Join(u.dataDir, "next"), []byte(dest), 0o600); err != nil {
		return "", err
	}
	return dest, nil
}

// verifyManifest is the RSA-PSS counterpart to backend's
// agents.VerifyBundleSig — the cloud signs manifest JSON, the agent
// rejects any divergence.
func verifyManifest(manifest []byte, sigB64 string, pub *rsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(manifest)
	return rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], sig, nil)
}

// Exposed for tests.
var _ = bytes.Buffer{}
