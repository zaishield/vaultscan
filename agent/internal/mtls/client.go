// Package mtls builds the *http.Client the agent uses to talk to the
// gateway when the gateway is configured for real mTLS. Combines:
//   - the agent's own keypair + cert (loaded from agent.crt / agent.key)
//   - the trusted server CA pool (loaded from gateway-ca.pem)
//
// In dev mode the gateway accepts plain HTTP + headers; this package is
// inert in that case — the existing http.DefaultClient stays in use.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/zaishield/vaultscan/agent/internal/certstore"
)

// Client builds an *http.Client wired with mTLS for talking to the
// gateway. Returns an error when any required artifact is missing —
// the agent's main loop logs and falls back to the dev HTTP client in
// that case.
//
//	cert.pem / key.pem        : agent's own client cert + private key
//	gateway-ca.pem (optional) : CA pool to verify the gateway's cert.
//	                            Empty = use the system pool.
func Client(dataDir string) (*http.Client, error) {
	b, err := certstore.Load(dataDir)
	if err != nil {
		return nil, err
	}
	leaf, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{leaf},
	}
	if caPath := filepath.Join(dataDir, "gateway-ca.pem"); fileExists(caPath) {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("mtls: gateway-ca.pem could not be parsed")
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       cfg,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          16,
		},
	}, nil
}

// UpdateClientCert swaps the leaf certificate in an existing
// http.Client's transport without dropping in-flight connections.
// Called by the rotation goroutine on a successful CSR cycle.
func UpdateClientCert(client *http.Client, dataDir string) error {
	if client == nil {
		return errors.New("mtls: nil client")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		return errors.New("mtls: client transport is not TLS-aware")
	}
	b, err := certstore.Load(dataDir)
	if err != nil {
		return err
	}
	leaf, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		return err
	}
	tr.TLSClientConfig.Certificates = []tls.Certificate{leaf}
	// Force a clean reuse cycle: close idle connections so the next
	// request re-handshakes with the new cert.
	tr.CloseIdleConnections()
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
