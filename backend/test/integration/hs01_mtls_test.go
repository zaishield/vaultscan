//go:build integration

// Real-mTLS integration test for the agent gateway. Spins up a TLS
// listener configured with agentgw.BuildTLSConfig, then exercises every
// rejection path with real x509 certs + an HTTP client.

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/agentgw"
	"github.com/zaishield/vaultscan/backend/internal/agents"
)

// caBundle is one issuer CA + a leaf cert signed by it.
type caBundle struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	caPEM  []byte
}

func newCA(t *testing.T, cn string) *caBundle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &caBundle{
		caCert: cert, caKey: key,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issueLeaf signs a leaf cert with the bundle CA, returns the tls.Certificate
// the client uses + the DER for fingerprinting. SANs include 127.0.0.1 and
// the CN so the cert works as both server (httptest) and client cert.
func (b *caBundle) issueLeaf(t *testing.T, cn string) (tls.Certificate, []byte) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, b.caCert, &key.PublicKey, b.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	leaf, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, der
}

// trustCA inserts the CA into agent_ca_certificates so NewCertVerifier
// picks it up.
func trustCA(t *testing.T, h *harness, name string, b *caBundle) {
	t.Helper()
	derSum := sha256.Sum256(b.caCert.Raw)
	fp := hex.EncodeToString(derSum[:])
	if _, err := h.pool.Exec(context.Background(), `
		INSERT INTO agent_ca_certificates(name, cert_pem, fingerprint, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5)`,
		name, string(b.caPEM), fp, b.caCert.NotBefore, b.caCert.NotAfter); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM agent_ca_certificates WHERE name=$1`, name)
	})
}

// registerAgentCert inserts the agent_certificates row keyed on a
// fingerprint we know maps to a leaf the test issued.
func registerAgentCert(t *testing.T, h *harness, agentID uuid.UUID, leafDER []byte, revoked bool) {
	t.Helper()
	sum := sha256.Sum256(leafDER)
	fp := hex.EncodeToString(sum[:])
	revokedAt := "NULL"
	args := []any{agentID, fp, "test-serial-" + fp[:8], time.Now().Add(365 * 24 * time.Hour)}
	q := `INSERT INTO agent_certificates(agent_id, fingerprint, serial, pem, expires_at)
	      VALUES ($1, $2, $3, '-----BEGIN CERT-----\nfake\n-----END CERT-----', $4)`
	if _, err := h.pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
	if revoked {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE agent_certificates SET revoked_at=now() WHERE fingerprint=$1`, fp)
	}
	_ = revokedAt
}

// mountGatewayTLS builds a TLS test server that runs the same auth
// middleware the production binary mounts.
func mountGatewayTLS(t *testing.T, h *harness, b *caBundle) (*httptest.Server, *http.Client) {
	t.Helper()
	verifier, err := agentgw.NewCertVerifier(context.Background(), h.pool)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	// Server cert: a self-signed leaf signed by the SAME CA so the
	// client also has the CA to verify the server.
	serverLeaf, _ := b.issueLeaf(t, "vaultscan-agent-gateway-test")
	srvCertPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: serverLeaf.Certificate[0],
	})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverLeaf.PrivateKey.(*rsa.PrivateKey)),
	})
	tlsConfig, err := agentgw.BuildTLSConfig(srvCertPEM, srvKeyPEM, verifier)
	if err != nil {
		t.Fatalf("build tls: %v", err)
	}

	// Tiny handler that just returns the resolved agent ID.
	mux := http.NewServeMux()
	mux.Handle("/api/v1/agents/whoami",
		agentgw.IdentityFromTLSMiddleware(h.pool)(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				agent := agentgw.AgentFromContext(r.Context())
				w.Write([]byte(agent.String()))
			})))

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = tlsConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(b.caPEM)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "127.0.0.1",
			},
		},
		Timeout: 10 * time.Second,
	}
	return srv, client
}

// TestHS01_MTLS_NoClientCertRejected: a client with no certificate fails
// the TLS handshake — never reaches the handler.
func TestHS01_MTLS_NoClientCertRejected(t *testing.T) {
	h := newHarness(t)
	ca := newCA(t, "vs-test-ca-no-cert")
	trustCA(t, h, "vs-test-ca-no-cert", ca)
	srv, client := mountGatewayTLS(t, h, ca)

	_, err := client.Get(srv.URL + "/api/v1/agents/whoami")
	if err == nil {
		t.Fatal("expected handshake failure when no client cert presented")
	}
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected TLS-level rejection, got: %v", err)
	}
}

// TestHS01_MTLS_UnknownFingerprintRejected: client presents a valid
// CA-signed cert that's never been registered → VerifyPeerCertificate
// returns ErrAgentCertRejected and the handshake fails with 'tls:
// unknown certificate' from the peer.
func TestHS01_MTLS_UnknownFingerprintRejected(t *testing.T) {
	h := newHarness(t)
	ca := newCA(t, "vs-test-ca-unknown")
	trustCA(t, h, "vs-test-ca-unknown", ca)
	srv, client := mountGatewayTLS(t, h, ca)

	leaf, _ := ca.issueLeaf(t, "unregistered-agent")
	// Inject the leaf into the client without registering it server-side.
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{leaf}

	_, err := client.Get(srv.URL + "/api/v1/agents/whoami")
	if err == nil {
		t.Fatal("expected rejection for unknown fingerprint")
	}
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected TLS rejection, got: %v", err)
	}

	// Handshake log shows the rejection reason.
	var decision string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT decision FROM agent_mtls_handshakes
		   WHERE decision LIKE 'rejected%' ORDER BY occurred_at DESC LIMIT 1`).
		Scan(&decision); err == nil {
		if !strings.HasPrefix(decision, "rejected_unknown") {
			t.Fatalf("expected rejected_unknown in handshake log, got %s", decision)
		}
	}
}

// TestHS01_MTLS_RevokedCertRejected: a CA-signed cert whose
// agent_certificates row has revoked_at set is rejected.
func TestHS01_MTLS_RevokedCertRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "mtls-revoked")

	ag, _, err := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "agent-revoked", FormFactor: "linux_vm", CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}

	ca := newCA(t, "vs-test-ca-revoked")
	trustCA(t, h, "vs-test-ca-revoked", ca)
	srv, client := mountGatewayTLS(t, h, ca)

	leaf, der := ca.issueLeaf(t, "agent-"+ag.ID.String())
	registerAgentCert(t, h, ag.ID, der, true /* revoked */)

	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{leaf}

	_, err = client.Get(srv.URL + "/api/v1/agents/whoami")
	if err == nil {
		t.Fatal("revoked cert must be rejected at TLS handshake")
	}

	var decision string
	_ = h.pool.QueryRow(ctx,
		`SELECT decision FROM agent_mtls_handshakes
		   WHERE agent_id=$1 ORDER BY occurred_at DESC LIMIT 1`,
		ag.ID).Scan(&decision)
	if !strings.HasPrefix(decision, "rejected_revoked") {
		t.Fatalf("expected rejected_revoked decision, got %q", decision)
	}
}

// TestHS01_MTLS_HappyPath: legitimate cert + registered, non-revoked
// fingerprint → request reaches handler with agent_id resolved.
func TestHS01_MTLS_HappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "mtls-happy")

	ag, _, err := h.agents.Provision(ctx, agents.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		Name: "agent-happy", FormFactor: "linux_vm", CreatedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}

	ca := newCA(t, "vs-test-ca-happy")
	trustCA(t, h, "vs-test-ca-happy", ca)
	srv, client := mountGatewayTLS(t, h, ca)

	leaf, der := ca.issueLeaf(t, "agent-"+ag.ID.String())
	registerAgentCert(t, h, ag.ID, der, false)

	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{leaf}

	resp, err := client.Get(srv.URL + "/api/v1/agents/whoami")
	if err != nil {
		t.Fatalf("legitimate cert must connect: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := strings.TrimSpace(string(body))
	if got != ag.ID.String() {
		t.Fatalf("whoami returned %q, want %s", got, ag.ID)
	}

	// Handshake row records accepted.
	var decision string
	_ = h.pool.QueryRow(ctx,
		`SELECT decision FROM agent_mtls_handshakes WHERE agent_id=$1
		  ORDER BY occurred_at DESC LIMIT 1`, ag.ID).Scan(&decision)
	if decision != "accepted" {
		t.Fatalf("expected accepted handshake, got %q", decision)
	}
}

// TestHS01_MTLS_FingerprintHelper: the helper used by both the cloud
// CSR endpoint and the agent enrollment code produces the same hex.
func TestHS01_MTLS_FingerprintHelper(t *testing.T) {
	ca := newCA(t, "fp-test")
	_, der := ca.issueLeaf(t, "leaf")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fp, err := agentgw.FingerprintPEMCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if fp != hex.EncodeToString(sum[:]) {
		t.Fatal("agentgw fingerprint != sha256(DER)")
	}
	// Bad PEM returns error.
	if _, err := agentgw.FingerprintPEMCert([]byte("not a pem")); err == nil {
		t.Fatal("non-PEM input must error")
	}
	_ = errors.New // keep import live
	_ = net.IP{}
}
