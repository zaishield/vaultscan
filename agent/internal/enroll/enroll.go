// Package enroll runs the one-time enrollment handshake (Blueprint §13.4).
// The agent generates a key pair, sends an enrollment token + cert PEM, and
// stores the cert fingerprint on disk for later mTLS.
package enroll

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/agent/internal/certstore"
)

func Run(client *http.Client, gateway string, agentID uuid.UUID, token, dataDir string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "vaultscan-agent-" + agentID.String()},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	sum := sha256.Sum256(certDER)
	fp := hex.EncodeToString(sum[:])

	body, _ := json.Marshal(map[string]string{
		"token": token, "cert_pem": string(certPEM), "fingerprint": fp,
	})
	req, err := http.NewRequest(http.MethodPost,
		gateway+"/api/v1/agents/"+agentID.String()+"/enroll",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("enroll: gateway returned %d", resp.StatusCode)
	}

	return certstore.Save(dataDir, certstore.Bundle{
		CertPEM:     string(certPEM),
		KeyPEM:      string(keyPEM),
		Fingerprint: fp,
	})
}

// LoadFingerprint reads the canonical bundle and returns its
// fingerprint, falling back to the legacy file for pre-bundle installs.
func LoadFingerprint(dataDir string) (string, error) {
	return certstore.LoadFingerprint(dataDir)
}
