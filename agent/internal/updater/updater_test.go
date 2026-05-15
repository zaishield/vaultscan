package updater

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// signManifest returns base64 RSA-PSS(sha256(m)) — the same algorithm
// the cloud's PublishBundle uses.
func signManifest(t *testing.T, key *rsa.PrivateKey, m Manifest) string {
	t.Helper()
	body, _ := json.Marshal(m)
	hashed := sha256.Sum256(body)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestUpdater_RejectsTamperedSignature(t *testing.T) {
	signerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()

	m := Manifest{
		TargetVersion: "1.2.0",
		DownloadURL:   "", // set after we know the test-server URL
		BundleSHA256:  "0000",
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	sig := signManifest(t, signerKey, m)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Tamper: change the target_version AFTER signing → signature
		// won't verify on the agent.
		tampered := m
		tampered.TargetVersion = "9.9.9-evil"
		_ = json.NewEncoder(w).Encode(Offer{
			ID: uuid.New(), Manifest: tampered, Signature: sig,
		})
	}))
	defer srv.Close()

	u := New(srv.Client(), srv.URL, uuid.New(), dir, &signerKey.PublicKey, "1.0.0")
	err := u.checkAndInstall(t.Context())
	if err == nil {
		t.Fatal("tampered manifest must be rejected")
	}
}

func TestUpdater_RejectsBundleHashMismatch(t *testing.T) {
	signerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()

	// Real bundle bytes the server will return.
	bundle := []byte("fake-binary-bytes-v1.2.0")
	realSum := sha256.Sum256(bundle)

	var bundleURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundle)
	})
	mux.HandleFunc("/api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		// Manifest claims a DIFFERENT sha256 from the actual bundle.
		m := Manifest{
			TargetVersion: "1.2.0",
			DownloadURL:   bundleURL,
			BundleSHA256:  "ff" + string(rune(0)), // intentionally wrong
			IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(Offer{
			ID: uuid.New(), Manifest: m, Signature: signManifest(t, signerKey, m),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	bundleURL = srv.URL + "/bundle"

	u := New(srv.Client(), srv.URL, uuid.New(), dir, &signerKey.PublicKey, "1.0.0")
	err := u.checkAndInstall(t.Context())
	if err == nil {
		t.Fatal("bundle hash mismatch must be rejected")
	}
	_ = realSum
}

func TestUpdater_HappyPathInstalls(t *testing.T) {
	signerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()

	bundle := []byte("fake-binary-bytes-v1.3.0")
	realSum := sha256.Sum256(bundle)
	hashHex := ""
	for _, b := range realSum {
		hashHex += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}

	var bundleURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundle)
	})
	mux.HandleFunc("/api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		m := Manifest{
			TargetVersion: "1.3.0",
			DownloadURL:   bundleURL,
			BundleSHA256:  hashHex,
			IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		}
		_ = json.NewEncoder(w).Encode(Offer{
			ID: uuid.New(), Manifest: m, Signature: signManifest(t, signerKey, m),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	bundleURL = srv.URL + "/bundle"

	installed := ""
	u := New(srv.Client(), srv.URL, uuid.New(), dir, &signerKey.PublicKey, "1.0.0")
	u.OnInstalled = func(t string) { installed = t }

	if err := u.checkAndInstall(t.Context()); err != nil {
		t.Fatalf("install: %v", err)
	}
	if installed == "" {
		t.Fatal("OnInstalled callback never fired")
	}
	// Bundle bytes landed on disk.
	got, err := os.ReadFile(installed)
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if string(got) != string(bundle) {
		t.Fatal("installed bundle bytes differ from served bytes")
	}
	// Next-pointer file exists.
	next, _ := os.ReadFile(filepath.Join(dir, "next"))
	if string(next) != installed {
		t.Fatalf("next pointer %q != installed %q", next, installed)
	}
	// CurrentVersion bumped — re-run is a no-op.
	if u.CurrentVersion != "1.3.0" {
		t.Fatalf("CurrentVersion not bumped: %q", u.CurrentVersion)
	}
}
