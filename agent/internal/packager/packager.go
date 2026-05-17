// Package packager bundles raw tool output into a tar.gz envelope
// containing stdout, stderr, and a manifest (tool + command line +
// timing + sha256 of each blob). The envelope is HMAC-signed with
// the agent's packager key so the gateway can detect tamper en route.
//
// Format (tar.gz):
//
//   manifest.json    — versioned JSON; carries tool name, command,
//                      timing, exit code, sha256 of stdout/stderr,
//                      and the HMAC over (manifest_bytes ++ stdout
//                      ++ stderr). Reading order matters: integrity
//                      is recomputed from the *raw* bytes inside the
//                      tar, not from the JSON's stated sha256
//                      (defence-in-depth).
//   stdout.bin       — raw scanner stdout
//   stderr.bin       — raw scanner stderr (may be empty)
//
// Backwards compatibility: a gateway that hasn't been upgraded yet
// will still receive a tar.gz body it can store as evidence; the
// signature header carries the HMAC so the existing /artifacts
// endpoint can validate without parsing the body.
package packager

import (
	"archive/tar"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zaishield/vaultscan/agent/internal/runner"
)

// EnvelopeVersion is bumped when manifest.json layout changes in a
// way that the gateway parser can't read both old + new formats.
const EnvelopeVersion = 1

// Manifest is the JSON sidecar embedded in every envelope.
type Manifest struct {
	Version     int       `json:"version"`
	Tool        string    `json:"tool"`
	Command     string    `json:"command"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	DurationMS  int64     `json:"duration_ms"`
	ExitCode    int       `json:"exit_code"`
	StdoutSize  int64     `json:"stdout_size"`
	StderrSize  int64     `json:"stderr_size"`
	StdoutSHA   string    `json:"stdout_sha256"`
	StderrSHA   string    `json:"stderr_sha256"`
	EnvelopeID  string    `json:"envelope_id"`   // random; lets the gateway dedup
	HMACEnvelop string    `json:"hmac_envelope"` // hex; over (manifest_no_hmac_bytes || stdout || stderr)
	// Synthetic = true when the agent fabricated the output because
	// the scanner binary was missing AND AllowSynthetic was set.
	// The gateway uses this to tag the upload as synthetic so it
	// does not flow into compliance metrics. Omit when false to
	// keep the manifest compact.
	Synthetic bool `json:"synthetic,omitempty"`
}

type Packager struct {
	// hmacKey is loaded from disk at agent boot. If empty (dev / first
	// boot), Package() falls back to writing the envelope without an
	// HMAC and the gateway treats it as unsigned (logged + flagged).
	hmacKey []byte
}

// New returns a packager with no HMAC key. Callers in production
// should construct via NewWithKey after loading the key from disk.
func New() *Packager { return &Packager{} }

// NewWithKey returns a packager that signs envelopes with the given
// 32-byte HMAC key. Anything shorter than 16 bytes is rejected.
func NewWithKey(key []byte) (*Packager, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("packager: hmac key must be >=16 bytes (got %d)", len(key))
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	return &Packager{hmacKey: cp}, nil
}

// LoadOrCreateKey reads dataDir/packager.key. If the file doesn't
// exist, generates a 32-byte key and writes it with mode 0600.
// Concurrent agent processes on the same dataDir would race here —
// don't run two agents pointing at the same dir.
func LoadOrCreateKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "packager.key")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) < 16 {
			return nil, fmt.Errorf("packager: %s is too short", path)
		}
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Package builds a tar.gz envelope from a runner.Output. Returns the
// envelope bytes and the hex HMAC (for the X-Vaultscan-Envelope-HMAC
// header). The HMAC is also embedded in manifest.json.
func (p *Packager) Package(out *runner.Output) ([]byte, string, error) {
	if out == nil {
		return nil, "", fmt.Errorf("packager: nil output")
	}
	stdoutHash := sha256.Sum256(out.Stdout)
	stderrHash := sha256.Sum256(out.Stderr)

	envID := make([]byte, 16)
	if _, err := rand.Read(envID); err != nil {
		return nil, "", err
	}
	m := Manifest{
		Version:    EnvelopeVersion,
		Tool:       out.Tool,
		Command:    out.Command,
		FinishedAt: time.Now().UTC(),
		StartedAt:  time.Now().UTC().Add(-out.Took),
		DurationMS: out.Took.Milliseconds(),
		ExitCode:   out.ExitCode,
		StdoutSize: int64(len(out.Stdout)),
		StderrSize: int64(len(out.Stderr)),
		StdoutSHA:  hex.EncodeToString(stdoutHash[:]),
		StderrSHA:  hex.EncodeToString(stderrHash[:]),
		EnvelopeID: hex.EncodeToString(envID),
		Synthetic:  out.Synthetic,
	}

	// Compute HMAC over (manifest_without_hmac || stdout || stderr).
	// The HMAC field is filled in after computing so it doesn't
	// chicken-and-egg the hash.
	mBytesNoHMAC, err := json.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	var hmacHex string
	if len(p.hmacKey) > 0 {
		mac := hmac.New(sha256.New, p.hmacKey)
		mac.Write(mBytesNoHMAC)
		mac.Write(out.Stdout)
		mac.Write(out.Stderr)
		hmacHex = hex.EncodeToString(mac.Sum(nil))
		m.HMACEnvelop = hmacHex
	}
	mBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", err
	}

	var bufW writeBuf
	gz := gzip.NewWriter(&bufW)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{
		{"manifest.json", mBytes},
		{"stdout.bin", out.Stdout},
		{"stderr.bin", out.Stderr},
	} {
		hdr := &tar.Header{
			Name:    f.name,
			Mode:    0o644,
			Size:    int64(len(f.body)),
			ModTime: m.FinishedAt,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(f.body); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}
	return bufW.b, hmacHex, nil
}

// writeBuf is a tiny io.Writer that doesn't import bytes (avoids
// an import cycle with the runner test packages that exercise this
// code as a black box).
type writeBuf struct{ b []byte }

func (w *writeBuf) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}
