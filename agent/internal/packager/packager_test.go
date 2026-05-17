package packager

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/zaishield/vaultscan/agent/internal/runner"
)

// Reads back the tar.gz envelope. Returns (manifest, stdout, stderr).
func unpack(t *testing.T, body []byte) (Manifest, []byte, []byte) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip open: %v", err)
	}
	tr := tar.NewReader(gz)
	var (
		manifest        Manifest
		stdout, stderr  []byte
		sawManifest     bool
	)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		b, _ := io.ReadAll(tr)
		switch h.Name {
		case "manifest.json":
			if err := json.Unmarshal(b, &manifest); err != nil {
				t.Fatalf("manifest unmarshal: %v", err)
			}
			sawManifest = true
		case "stdout.bin":
			stdout = b
		case "stderr.bin":
			stderr = b
		}
	}
	if !sawManifest {
		t.Fatal("envelope missing manifest.json")
	}
	return manifest, stdout, stderr
}

func TestPackager_BuildsValidEnvelope(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	p, err := NewWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	out := &runner.Output{
		Tool:    "nmap",
		Command: "nmap -sV target",
		Stdout:  []byte("port 80 open"),
		Stderr:  []byte("warning: deprecated"),
		ExitCode: 0,
	}
	body, hmacHex, err := p.Package(out)
	if err != nil {
		t.Fatal(err)
	}
	if hmacHex == "" {
		t.Fatal("expected non-empty hmac with a key wired")
	}
	m, gotStdout, gotStderr := unpack(t, body)
	if m.Tool != "nmap" || m.ExitCode != 0 {
		t.Errorf("manifest fields wrong: %+v", m)
	}
	if string(gotStdout) != "port 80 open" {
		t.Errorf("stdout corrupted: %q", gotStdout)
	}
	if string(gotStderr) != "warning: deprecated" {
		t.Errorf("stderr corrupted: %q", gotStderr)
	}
	if m.HMACEnvelop != hmacHex {
		t.Errorf("manifest hmac %q != returned hmac %q", m.HMACEnvelop, hmacHex)
	}
}

func TestPackager_HMACVerifiesTamper(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x55}, 32)
	p, _ := NewWithKey(key)
	body, hmacHex, _ := p.Package(&runner.Output{
		Tool: "nuclei", Command: "nuclei -u x", Stdout: []byte("ok"),
	})
	m, stdout, stderr := unpack(t, body)
	// Recompute HMAC over manifest-without-hmac || stdout || stderr.
	mCopy := m
	mCopy.HMACEnvelop = ""
	noHmacBytes, _ := json.Marshal(mCopy)
	mac := hmac.New(sha256.New, key)
	mac.Write(noHmacBytes)
	mac.Write(stdout)
	mac.Write(stderr)
	if hex.EncodeToString(mac.Sum(nil)) != hmacHex {
		t.Errorf("recomputed HMAC does not match returned HMAC — packager order is wrong")
	}
}

func TestPackager_NoKey_NoHMACButStillValid(t *testing.T) {
	t.Parallel()
	p := New()
	body, hmacHex, err := p.Package(&runner.Output{
		Tool: "trivy", Command: "trivy image x", Stdout: []byte("scan"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if hmacHex != "" {
		t.Errorf("expected empty hmac with no key wired, got %q", hmacHex)
	}
	m, _, _ := unpack(t, body)
	if m.Tool != "trivy" {
		t.Errorf("manifest tool wrong: %s", m.Tool)
	}
	if m.HMACEnvelop != "" {
		t.Errorf("manifest hmac should be empty: %q", m.HMACEnvelop)
	}
}

func TestPackager_RejectsShortKey(t *testing.T) {
	t.Parallel()
	if _, err := NewWithKey([]byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestLoadOrCreateKey_PersistsAcrossCalls(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Errorf("LoadOrCreateKey returned different keys on consecutive calls")
	}
	st, _ := os.Stat(filepath.Join(dir, "packager.key"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", st.Mode().Perm())
	}
}
