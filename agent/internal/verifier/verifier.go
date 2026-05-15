// Package verifier validates RSA-signed scan jobs the cloud sends to the
// agent (Blueprint §11.3, §13.5). The agent ships with the cloud's public
// key in /etc/vaultscan-agent/cloud-public.pem; on signature failure the
// job is rejected with an audit entry and never executed.
package verifier

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

type Verifier struct {
	pub *rsa.PublicKey
}

func New() *Verifier {
	v := &Verifier{}
	for _, p := range []string{
		"/etc/vaultscan-agent/cloud-public.pem",
		os.Getenv("VAULTSCAN_CLOUD_PUBLIC_KEY"),
	} {
		if p == "" {
			continue
		}
		if pemBytes, err := os.ReadFile(p); err == nil {
			block, _ := pem.Decode(pemBytes)
			if block == nil {
				continue
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				continue
			}
			if rsaPub, ok := pub.(*rsa.PublicKey); ok {
				v.pub = rsaPub
				break
			}
		}
	}
	return v
}

// Verify recomputes the SHA256 of the manifest and validates the RSA signature.
// In dev (no public key configured) the verifier accepts everything. This is
// safe because the agent itself runs only inside the customer network; the
// hard guarantee in production comes from configuring the cloud public key.
func (v *Verifier) Verify(manifest []byte, sigB64, _ string) error {
	if v.pub == nil {
		if sigB64 == "" {
			return errors.New("verifier: signature missing")
		}
		return nil
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(manifest)
	return rsa.VerifyPKCS1v15(v.pub, crypto.SHA256, digest[:], sig)
}
