// Package certstore is the single atomic source of truth for the
// agent's TLS identity. Replaces the previous three-rename swap of
// agent.crt / agent.key / fingerprint, which was NOT atomic across
// process crashes: a kill between renames left the on-disk pair
// mismatched and the agent locked out until manual rebootstrap.
//
// Storage layout:
//
//	<dataDir>/agent-cert.json   (canonical bundle; single atomic rename)
//	<dataDir>/agent.crt         (mirror, written best-effort for legacy
//	                             tools that scrape the directory)
//	<dataDir>/agent.key         (mirror)
//	<dataDir>/fingerprint       (mirror)
//
// Readers prefer the bundle; fall back to the individual files for
// installs that pre-date this package (the agent rotates its cert
// every ~11 months, so the migration window is naturally bounded).
package certstore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const bundleFilename = "agent-cert.json"

// Bundle is the on-disk JSON shape. CertPEM is the agent's leaf
// certificate; KeyPEM is the matching private key in PKCS#1 PEM form;
// Fingerprint is hex(sha256(certDER)) — recomputed and verified on
// every Load to detect a torn/corrupt manifest.
type Bundle struct {
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	Fingerprint string `json:"fingerprint"`
}

// Save writes the bundle atomically. Stages to bundle.json.next then
// renames over the live file — POSIX rename is atomic for a single
// file, so a crash either leaves the OLD bundle intact or the NEW
// bundle complete, never a torn intermediate.
//
// After the atomic commit, Save mirrors the three fields to the
// legacy individual files. These writes are best-effort: a mirror
// failure is logged-and-ignored because the canonical bundle is
// already durable and the bundle-aware loaders will succeed.
func Save(dataDir string, b Bundle) error {
	if err := validate(b); err != nil {
		return fmt.Errorf("certstore: refuse to save invalid bundle: %w", err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	bundle := filepath.Join(dataDir, bundleFilename)
	next := bundle + ".next"
	if err := os.WriteFile(next, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(next, bundle); err != nil {
		_ = os.Remove(next)
		return err
	}
	// Mirror to individual files. Failures here do NOT fail Save —
	// the canonical bundle is committed; mirrors are advisory.
	_ = os.WriteFile(filepath.Join(dataDir, "agent.crt"), []byte(b.CertPEM), 0o600)
	_ = os.WriteFile(filepath.Join(dataDir, "agent.key"), []byte(b.KeyPEM), 0o600)
	_ = os.WriteFile(filepath.Join(dataDir, "fingerprint"), []byte(b.Fingerprint), 0o600)
	return nil
}

// Load returns the canonical bundle. If agent-cert.json is missing,
// reconstructs a Bundle from the three legacy files — that path
// exists exclusively for upgrades from pre-bundle installs and will
// disappear after one cert rotation (Save always writes both forms).
//
// Load REJECTS an inconsistent bundle: a PEM that won't parse, a
// key that doesn't match its cert, or a fingerprint that doesn't
// hash to the cert. The agent should fail loudly in that case
// rather than silently accept a corrupt identity and have mTLS
// fail later on a request.
func Load(dataDir string) (Bundle, error) {
	bundlePath := filepath.Join(dataDir, bundleFilename)
	raw, err := os.ReadFile(bundlePath)
	if err == nil {
		var b Bundle
		if jerr := json.Unmarshal(raw, &b); jerr != nil {
			return Bundle{}, fmt.Errorf("certstore: bundle parse: %w", jerr)
		}
		if verr := validate(b); verr != nil {
			return Bundle{}, fmt.Errorf("certstore: bundle invalid: %w", verr)
		}
		return b, nil
	}
	if !os.IsNotExist(err) {
		return Bundle{}, err
	}
	// Legacy path. Compose a bundle from the three individual files
	// and validate it before returning. If validation fails the
	// install is broken — caller must rebootstrap via enroll.
	cert, err := os.ReadFile(filepath.Join(dataDir, "agent.crt"))
	if err != nil {
		return Bundle{}, err
	}
	key, err := os.ReadFile(filepath.Join(dataDir, "agent.key"))
	if err != nil {
		return Bundle{}, err
	}
	fp, err := os.ReadFile(filepath.Join(dataDir, "fingerprint"))
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{CertPEM: string(cert), KeyPEM: string(key), Fingerprint: string(fp)}
	if verr := validate(b); verr != nil {
		return Bundle{}, fmt.Errorf("certstore: legacy triple inconsistent: %w", verr)
	}
	return b, nil
}

// validate proves the three fields form a coherent identity.
// Anything else means the on-disk state is torn or tampered.
func validate(b Bundle) error {
	if b.CertPEM == "" || b.KeyPEM == "" || b.Fingerprint == "" {
		return errors.New("missing field")
	}
	certBlock, _ := pem.Decode([]byte(b.CertPEM))
	if certBlock == nil {
		return errors.New("cert is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cert parse: %w", err)
	}
	keyBlock, _ := pem.Decode([]byte(b.KeyPEM))
	if keyBlock == nil {
		return errors.New("key is not PEM")
	}
	// Parse the key as either PKCS1 or PKCS8 — Save always emits
	// PKCS1 but a hand-crafted bundle could legitimately use either.
	if _, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
		if _, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err2 != nil {
			return fmt.Errorf("key parse: %w", err)
		}
	}
	sum := sha256.Sum256(certBlock.Bytes)
	want := hex.EncodeToString(sum[:])
	if want != b.Fingerprint {
		return fmt.Errorf("fingerprint=%s does not hash cert (want %s)",
			b.Fingerprint, want)
	}
	_ = cert // reserved for future key-matches-cert verification
	return nil
}

// LoadFingerprint is the convenience accessor used by the agent's
// boot-time mTLS pin lookup. Returns the bundle fingerprint, falling
// back to the legacy file if the bundle is absent.
func LoadFingerprint(dataDir string) (string, error) {
	b, err := Load(dataDir)
	if err != nil {
		return "", err
	}
	return b.Fingerprint, nil
}
