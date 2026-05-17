package mtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zaishield/vaultscan/agent/internal/certstore"
)

// makeCertKey returns a self-signed cert+key written to dataDir as
// agent.crt / agent.key. The CA is the cert itself (self-signed).
func makeCertKey(t *testing.T, dataDir, cn string) ([]byte, []byte) {
	t.Helper()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if dataDir != "" {
		// Use the canonical bundle so the test exercises the same path
		// the agent uses in production.
		sum := sha256.Sum256(der)
		if err := certstore.Save(dataDir, certstore.Bundle{
			CertPEM:     string(certPEM),
			KeyPEM:      string(keyPEM),
			Fingerprint: hex.EncodeToString(sum[:]),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return certPEM, keyPEM
}

func TestClient_BuildsMTLSConfig(t *testing.T) {
	dir := t.TempDir()
	makeCertKey(t, dir, "test-agent")

	c, err := Client(dir)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	tr, _ := c.Transport.(*http.Transport)
	if tr == nil || tr.TLSClientConfig == nil {
		t.Fatal("transport missing TLS config")
	}
	if len(tr.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("expected 1 client cert, got %d", len(tr.TLSClientConfig.Certificates))
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 min, got %d", tr.TLSClientConfig.MinVersion)
	}
}

func TestClient_MissingCertReturnsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := Client(dir); err == nil {
		t.Fatal("Client must fail when agent.crt/agent.key are absent")
	}
}

func TestUpdateClientCert_HotSwap(t *testing.T) {
	dir := t.TempDir()
	makeCertKey(t, dir, "original")

	c, err := Client(dir)
	if err != nil {
		t.Fatal(err)
	}
	original := c.Transport.(*http.Transport).TLSClientConfig.Certificates[0]

	// Write a new cert into the same paths.
	makeCertKey(t, dir, "rotated")
	if err := UpdateClientCert(c, dir); err != nil {
		t.Fatalf("UpdateClientCert: %v", err)
	}
	updated := c.Transport.(*http.Transport).TLSClientConfig.Certificates[0]
	if string(original.Certificate[0]) == string(updated.Certificate[0]) {
		t.Fatal("certificate didn't change after UpdateClientCert")
	}
}

// TestClient_EndToEndAgainstTLSServer proves the assembled client can
// complete a TLS 1.3 handshake against a server that requires a client
// cert + verifies it via VerifyPeerCertificate. Doesn't need the
// gateway code — just the same primitives.
func TestClient_EndToEndAgainstTLSServer(t *testing.T) {
	dir := t.TempDir()
	clientCert, _ := makeCertKey(t, dir, "client-agent")
	// Server cert: separately issued.
	serverCertPEM, serverKeyPEM := makeCertKey(t, "", "server-side")

	// Place server CA in dataDir so the client trusts it.
	if err := os.WriteFile(filepath.Join(dir, "gateway-ca.pem"), serverCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(clientCert)

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no peer cert", 495)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello-" + r.TLS.PeerCertificates[0].Subject.CommonName))
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	srv.StartTLS()
	defer srv.Close()

	c, err := Client(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Force the client's SNI to "127.0.0.1" (matches the SAN).
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "127.0.0.1"

	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-client-agent" {
		t.Fatalf("server didn't see the right client cert: %q", body)
	}
}
