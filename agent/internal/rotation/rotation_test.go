package rotation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedExpiringCert writes an agent.crt that's already inside RotateBefore
// so dueForRotation returns true.
func seedExpiringCert(t *testing.T, dir string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stale"},
		NotBefore:    time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour), // 7 days = inside rotateBefore (30d)
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key"),
		pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fingerprint"), []byte("old-fp"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mockCA signs whatever CSR comes in and serves the result on /csr.
func mockCSRServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/csr") {
			http.NotFound(w, r)
			return
		}
		var req struct {
			CSRPem string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		block, _ := pem.Decode([]byte(req.CSRPem))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			http.Error(w, "bad csr signature", 400)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      csr.Subject,
			NotBefore:    time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		sum := sha256.Sum256(der)
		fp := hex.EncodeToString(sum[:])
		_ = json.NewEncoder(w).Encode(map[string]string{
			"certificate_pem": string(certPEM), "fingerprint": fp,
		})
	})
	return httptest.NewServer(mux), caKey
}

func TestRotation_DueWhenWithinWindow(t *testing.T) {
	dir := t.TempDir()
	seedExpiringCert(t, dir)
	r := New(http.DefaultClient, "", uuid.New(), dir, "old-fp")
	due, err := r.dueForRotation()
	if err != nil {
		t.Fatal(err)
	}
	if !due {
		t.Fatal("cert expiring in 7d must be due (RotateBefore=30d)")
	}
}

func TestRotation_AtomicSwapOnSuccess(t *testing.T) {
	dir := t.TempDir()
	seedExpiringCert(t, dir)
	srv, _ := mockCSRServer(t)
	defer srv.Close()

	r := New(srv.Client(), srv.URL, uuid.New(), dir, "old-fp")
	if err := r.rotateOnce(t.Context()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Cert was replaced with a fresh one well outside RotateBefore.
	due, _ := r.dueForRotation()
	if due {
		t.Fatal("post-rotation cert must be outside the rotate window")
	}
	// Fingerprint updated.
	if r.Fingerprint() == "old-fp" {
		t.Fatal("Fingerprint() not updated after rotation")
	}
	// On-disk fingerprint matches in-memory.
	on, _ := os.ReadFile(filepath.Join(dir, "fingerprint"))
	if string(on) != r.Fingerprint() {
		t.Fatalf("on-disk fp %q != in-memory %q", on, r.Fingerprint())
	}
}

func TestRotation_RejectsServerLies(t *testing.T) {
	dir := t.TempDir()
	seedExpiringCert(t, dir)
	// Server returns a cert + a FINGERPRINT that doesn't match it.
	lying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// emit a self-signed cert but a bogus fingerprint
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1),
			Subject: pkix.Name{CommonName: "x"},
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = json.NewEncoder(w).Encode(map[string]string{
			"certificate_pem": string(certPEM),
			"fingerprint":     "deadbeef-lying-fp",
		})
	}))
	defer lying.Close()
	r := New(lying.Client(), lying.URL, uuid.New(), dir, "old-fp")
	err := r.rotateOnce(t.Context())
	if err == nil {
		t.Fatal("rotator must refuse a server-supplied fingerprint that doesn't hash the cert")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint-mismatch error, got %v", err)
	}
}

// silence unused import in older Go
var _ = io.EOF
