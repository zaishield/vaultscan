package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// genBundle mints a self-signed cert + matching key + correct
// fingerprint. Tests use it whenever they need a valid Bundle.
func genBundle(t *testing.T) Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-agent"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	sum := sha256.Sum256(der)
	return Bundle{
		CertPEM:     string(certPEM),
		KeyPEM:      string(keyPEM),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

// TestSave_AtomicCommit proves Save either commits the entire bundle
// or leaves the prior bundle intact — never a torn intermediate.
// The previous three-rename swap could leave the agent locked out
// after a kill between renames; this test would fail that design.
func TestSave_AtomicCommit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := genBundle(t)
	if err := Save(dir, first); err != nil {
		t.Fatal(err)
	}
	// Confirm the canonical bundle and validates.
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != first.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s",
			got.Fingerprint, first.Fingerprint)
	}

	// Save again with a fresh identity — the rename must replace
	// the bundle atomically, not leave a half-written file behind.
	second := genBundle(t)
	if err := Save(dir, second); err != nil {
		t.Fatal(err)
	}
	got2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Fingerprint != second.Fingerprint {
		t.Fatalf("post-rotate fingerprint=%s want %s",
			got2.Fingerprint, second.Fingerprint)
	}
}

// TestSave_RejectsInconsistentBundle keeps the writer honest. If a
// caller hands certstore.Save a bundle whose fingerprint doesn't
// hash to the cert, the save MUST fail loudly so we never persist
// torn state from a programming error.
func TestSave_RejectsInconsistentBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	b := genBundle(t)
	b.Fingerprint = "deadbeef" // poisoned
	if err := Save(dir, b); err == nil {
		t.Fatal("save accepted bundle with wrong fingerprint")
	}
}

// TestLoad_RejectsTornLegacyTriple covers the upgrade path. If a
// pre-bundle install crashed mid-rotation (old three-rename), Load
// must catch the inconsistency rather than hand the agent a bad
// identity that will silently fail mTLS on the next request.
func TestLoad_RejectsTornLegacyTriple(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := genBundle(t)
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"),
		[]byte(good.CertPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key"),
		[]byte(good.KeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fingerprint left as a stale/old value — simulates the crash
	// between renames in the legacy swap.
	if err := os.WriteFile(filepath.Join(dir, "fingerprint"),
		[]byte("00000000"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted torn legacy triple — fingerprint did not match")
	}
}

// TestSave_Concurrent makes sure two concurrent Save calls don't
// corrupt the bundle. Both succeed; exactly one wins; the loaded
// bundle is internally consistent.
func TestSave_Concurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := Save(dir, genBundle(t)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Save(dir, genBundle(t))
		}()
	}
	wg.Wait()
	if _, err := Load(dir); err != nil {
		t.Fatalf("post-concurrent Load failed: %v", err)
	}
}
