package verifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func makeKeyAndPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return priv, string(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	}))
}

func TestVerifier_RefusesWithoutKey(t *testing.T) {
	v := &Verifier{}
	if v.Loaded() {
		t.Error("fresh Verifier should not be Loaded")
	}
	if err := v.Verify([]byte("manifest"), "sig", ""); err == nil {
		t.Error("Verify without key should error")
	}
}

func TestVerifier_LoadsKeyFromEnvLiteral(t *testing.T) {
	_, pemStr := makeKeyAndPEM(t)
	t.Setenv("VAULTSCAN_CLOUD_PUBLIC_KEY", pemStr)
	v := New()
	if !v.Loaded() {
		t.Error("expected key loaded from env literal")
	}
}

func TestVerifier_LoadsKeyFromFilePath(t *testing.T) {
	dir := t.TempDir()
	_, pemStr := makeKeyAndPEM(t)
	path := filepath.Join(dir, "cloud-public.pem")
	_ = os.WriteFile(path, []byte(pemStr), 0o600)

	t.Setenv("VAULTSCAN_CLOUD_PUBLIC_KEY", path)
	v := New()
	if !v.Loaded() {
		t.Error("expected key loaded from file path")
	}
}

func TestVerifier_VerifyHappyPath(t *testing.T) {
	priv, pemStr := makeKeyAndPEM(t)
	v := &Verifier{}
	if !v.tryLoad([]byte(pemStr)) {
		t.Fatal("tryLoad failed")
	}
	manifest := []byte(`{"job":"abc","tools":["nmap"]}`)
	digest := sha256.Sum256(manifest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(manifest, base64.StdEncoding.EncodeToString(sig), ""); err != nil {
		t.Errorf("Verify returned %v", err)
	}
}

func TestVerifier_VerifyTamperedManifestRejected(t *testing.T) {
	priv, pemStr := makeKeyAndPEM(t)
	v := &Verifier{}
	v.tryLoad([]byte(pemStr))
	manifest := []byte(`{"job":"abc","tools":["nmap"]}`)
	digest := sha256.Sum256(manifest)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])

	// Tamper.
	tampered := []byte(`{"job":"abc","tools":["hydra"]}`)
	if err := v.Verify(tampered, base64.StdEncoding.EncodeToString(sig), ""); err == nil {
		t.Error("expected verify failure on tampered manifest")
	}
}

func TestVerifier_VerifyEmptySignatureRejected(t *testing.T) {
	_, pemStr := makeKeyAndPEM(t)
	v := &Verifier{}
	v.tryLoad([]byte(pemStr))
	if err := v.Verify([]byte("x"), "", ""); err == nil {
		t.Error("expected error on empty signature")
	}
}

func TestVerifier_FetchAndPersist(t *testing.T) {
	_, pemStr := makeKeyAndPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/orchestrator/public-key" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(pemStr))
	}))
	defer srv.Close()

	dir := t.TempDir()
	v := &Verifier{}
	if err := v.FetchAndPersist(context.Background(), srv.URL, dir); err != nil {
		t.Fatal(err)
	}
	if !v.Loaded() {
		t.Error("expected key loaded after FetchAndPersist")
	}
	// Cached file written?
	if _, err := os.Stat(filepath.Join(dir, "cloud-public.pem")); err != nil {
		t.Errorf("expected cached PEM file: %v", err)
	}
}

func TestVerifier_FetchAndPersist_RejectsBadPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not a PEM"))
	}))
	defer srv.Close()
	v := &Verifier{}
	if err := v.FetchAndPersist(context.Background(), srv.URL, t.TempDir()); err == nil {
		t.Error("expected error on non-PEM response")
	}
}

func TestVerifier_FetchAndPersist_RejectsEmptyURL(t *testing.T) {
	v := &Verifier{}
	if err := v.FetchAndPersist(context.Background(), "", ""); err == nil {
		t.Error("expected error when API URL empty")
	}
}
