// Package cosign verifies container-image signatures produced by Sigstore's
// cosign tool (https://github.com/sigstore/cosign) against a configured
// trust policy.
//
// Cosign signs a SimpleSigning JSON envelope of the shape:
//
//	{
//	  "critical": {
//	    "identity": {"docker-reference": "registry/repo:tag"},
//	    "image":    {"docker-manifest-digest": "sha256:..."},
//	    "type":     "cosign container image signature"
//	  },
//	  "optional": {...}
//	}
//
// The signature is an ECDSA-P256-SHA256 (default) or RSA-PSS-SHA256 over
// the canonical JSON bytes. The signer's public key (or, in keyless mode,
// a Fulcio-issued cert) lives next to the image in the OCI registry under
// the `<digest>.sig` tag.
//
// This package implements key-based verification — the deterministic,
// air-gappable path. Keyless (Sigstore Fulcio + Rekor) is a separate
// effort that this code is designed to slot into without re-architecting.
package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Decision codes correspond to cosign_verifications.decision values.
const (
	DecisionAccepted          = "accepted"
	DecisionRejectedSignature = "rejected_signature"
	DecisionRejectedUnknownKey = "rejected_unknown_key"
	DecisionRejectedDisabled  = "rejected_disabled"
	DecisionRejectedSubject   = "rejected_subject"
	DecisionRejectedPayload   = "rejected_payload"
)

type Service struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// TrustedKey is one row of the cosign_trusted_keys table parsed into the
// verifier's working form.
type TrustedKey struct {
	ID            uuid.UUID
	KeyID         string
	Algorithm     string
	Plane         string
	Subject       string
	Issuer        string
	Enabled       bool
	parsedPublic  any
}

// LoadActiveKeys returns every enabled, non-revoked trusted key for the
// requested plane (external | internal | both). Caller can cache the
// result; the scanner worker refreshes once per minute in production.
func (s *Service) LoadActiveKeys(ctx context.Context, plane string) ([]TrustedKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, key_id, algorithm, public_key_pem,
		       plane, COALESCE(subject,''), COALESCE(issuer,''), enabled
		  FROM cosign_trusted_keys
		 WHERE enabled = true
		   AND revoked_at IS NULL
		   AND (plane = $1 OR plane = 'both')`, plane)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedKey
	for rows.Next() {
		var (
			id                 uuid.UUID
			keyID, algo, pem   string
			pln, subj, issuer  string
			enabled            bool
		)
		if err := rows.Scan(&id, &keyID, &algo, &pem, &pln, &subj, &issuer, &enabled); err != nil {
			return nil, err
		}
		pub, err := ParsePublicKey(pem)
		if err != nil {
			// Skip unparseable keys — log via the caller, don't poison the slice.
			continue
		}
		out = append(out, TrustedKey{
			ID: id, KeyID: keyID, Algorithm: algo, Plane: pln,
			Subject: subj, Issuer: issuer, Enabled: enabled,
			parsedPublic: pub,
		})
	}
	return out, rows.Err()
}

// Register inserts a new trusted key. Used by /api/v1/cosign/keys.
type RegisterInput struct {
	KeyID        string
	Algorithm    string   // ecdsa-p256-sha256 | rsa-pss-sha256
	PublicKeyPEM string
	Plane        string   // external | internal | both
	Subject      string
	Issuer       string
	RegisteredBy *uuid.UUID
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (uuid.UUID, error) {
	if in.KeyID == "" || in.PublicKeyPEM == "" || in.Algorithm == "" {
		return uuid.Nil, errors.New("cosign: key_id + algorithm + public_key_pem required")
	}
	if _, err := ParsePublicKey(in.PublicKeyPEM); err != nil {
		return uuid.Nil, fmt.Errorf("cosign: invalid PEM: %w", err)
	}
	if in.Plane == "" {
		in.Plane = "both"
	}
	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO cosign_trusted_keys(id, key_id, algorithm, public_key_pem,
		    plane, subject, issuer, registered_by)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''), $8)`,
		id, in.KeyID, in.Algorithm, in.PublicKeyPEM, in.Plane,
		in.Subject, in.Issuer, in.RegisteredBy); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// Revoke disables a key. We don't hard-delete so the audit trail of past
// verifications stays meaningful.
func (s *Service) Revoke(ctx context.Context, keyID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE cosign_trusted_keys SET enabled=false, revoked_at=now() WHERE key_id=$1`, keyID)
	return err
}

// ListKeys returns all keys regardless of state (for the admin UI).
func (s *Service) ListKeys(ctx context.Context) ([]TrustedKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, key_id, algorithm, public_key_pem,
		       plane, COALESCE(subject,''), COALESCE(issuer,''), enabled
		  FROM cosign_trusted_keys ORDER BY registered_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedKey
	for rows.Next() {
		var (
			id                 uuid.UUID
			keyID, algo, pemS  string
			pln, subj, issuer  string
			enabled            bool
		)
		if err := rows.Scan(&id, &keyID, &algo, &pemS, &pln, &subj, &issuer, &enabled); err != nil {
			return nil, err
		}
		out = append(out, TrustedKey{
			ID: id, KeyID: keyID, Algorithm: algo, Plane: pln,
			Subject: subj, Issuer: issuer, Enabled: enabled,
		})
	}
	return out, rows.Err()
}

// ----- Verification --------------------------------------------------------

// Bundle is the minimum a cosign signature ships with: the SimpleSigning
// payload (base64 JSON) and the raw signature (base64). Production may also
// have a Rekor inclusion proof we keep optional here.
type Bundle struct {
	PayloadB64   string `json:"payload"`
	SignatureB64 string `json:"signature"`
	KeyID        string `json:"key_id,omitempty"`   // hint; we also try every active key
	Subject      string `json:"subject,omitempty"`  // for keyless verification (future)
}

// Result is the outcome the registry persists in cosign_verifications.
type Result struct {
	Decision   string
	Reason     string
	MatchedKey string
	Digest     string
}

// VerifyImage validates that `bundle` is a cosign signature over the
// expected image digest, signed by one of the trust-policy keys. Returns
// a Result describing the decision; the caller is responsible for the
// audit row + the accept/reject action.
func (s *Service) VerifyImage(ctx context.Context, imageRef, expectedDigest string, bundle Bundle, plane string) (*Result, error) {
	r := &Result{Digest: expectedDigest}

	// Decode + parse the SimpleSigning payload first. If the payload says
	// it covers a different digest, reject before bothering with crypto.
	payloadBytes, err := base64.StdEncoding.DecodeString(bundle.PayloadB64)
	if err != nil {
		r.Decision, r.Reason = DecisionRejectedPayload, "payload not base64: "+err.Error()
		return r, nil
	}
	var env struct {
		Critical struct {
			Identity struct{ DockerReference string `json:"docker-reference"` } `json:"identity"`
			Image    struct{ DockerManifestDigest string `json:"docker-manifest-digest"` } `json:"image"`
			Type     string `json:"type"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payloadBytes, &env); err != nil {
		r.Decision, r.Reason = DecisionRejectedPayload, "payload not JSON: "+err.Error()
		return r, nil
	}
	if env.Critical.Type != "cosign container image signature" {
		r.Decision, r.Reason = DecisionRejectedPayload,
			"payload critical.type is "+env.Critical.Type+", expected cosign container image signature"
		return r, nil
	}
	if env.Critical.Image.DockerManifestDigest != expectedDigest {
		r.Decision, r.Reason = DecisionRejectedPayload, fmt.Sprintf(
			"payload covers %s, expected %s",
			env.Critical.Image.DockerManifestDigest, expectedDigest)
		return r, nil
	}
	if imageRef != "" && !strings.Contains(env.Critical.Identity.DockerReference, imageRef) &&
		!strings.Contains(imageRef, env.Critical.Identity.DockerReference) {
		r.Decision, r.Reason = DecisionRejectedPayload, fmt.Sprintf(
			"payload identity %q doesn't match requested %s",
			env.Critical.Identity.DockerReference, imageRef)
		return r, nil
	}

	sig, err := base64.StdEncoding.DecodeString(bundle.SignatureB64)
	if err != nil {
		r.Decision, r.Reason = DecisionRejectedSignature, "signature not base64: "+err.Error()
		return r, nil
	}

	keys, err := s.LoadActiveKeys(ctx, plane)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		r.Decision, r.Reason = DecisionRejectedUnknownKey, "no active trusted keys for plane "+plane
		return r, nil
	}

	// Try every active key — cosign supports multiple signatures per image.
	digest := sha256.Sum256(payloadBytes)
	for _, k := range keys {
		// If the bundle hints at a key id, prefer that one but still allow
		// any other to pass — operators commonly co-sign during rotation.
		if bundle.KeyID != "" && k.KeyID != bundle.KeyID {
			continue
		}
		if verifyPubKey(k.parsedPublic, k.Algorithm, digest[:], sig) {
			r.Decision = DecisionAccepted
			r.MatchedKey = k.KeyID
			return r, nil
		}
	}
	// If the bundle's key hint matched nothing above, fall back to trying
	// every active key regardless of hint.
	if bundle.KeyID != "" {
		for _, k := range keys {
			if verifyPubKey(k.parsedPublic, k.Algorithm, digest[:], sig) {
				r.Decision = DecisionAccepted
				r.MatchedKey = k.KeyID
				r.Reason = "matched via fallback after key_id hint mismatch"
				return r, nil
			}
		}
	}
	r.Decision = DecisionRejectedSignature
	r.Reason = "no active trusted key produced this signature"
	return r, nil
}

// LogDecision persists the outcome to cosign_verifications.
func (s *Service) LogDecision(ctx context.Context, imageRef string, r *Result, actor *uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cosign_verifications(image_ref, image_digest, key_id, decision, reason, actor_id)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6)`,
		imageRef, r.Digest, r.MatchedKey, r.Decision, r.Reason, actor)
	return err
}

// CacheVerifiedSignature stores the accepted signature on the registry row
// so future scanner workers can skip the verification round-trip.
func (s *Service) CacheVerifiedSignature(ctx context.Context, imageRef string,
	bundle Bundle, keyID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scanner_image_registry
		   SET cosign_payload    = $2,
		       cosign_signature  = $3,
		       cosign_key_id     = $4,
		       cosign_verified_at = now()
		 WHERE image_ref = $1`,
		imageRef, bundle.PayloadB64, bundle.SignatureB64, keyID)
	return err
}

// ----- Crypto primitives ---------------------------------------------------

// ParsePublicKey accepts either ECDSA or RSA SubjectPublicKeyInfo PEM.
func ParsePublicKey(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("cosign: no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// cosign emits raw PKIX; fall back to PKCS1 for RSA legacy keys.
		if rsaPub, err2 := x509.ParsePKCS1PublicKey(block.Bytes); err2 == nil {
			return rsaPub, nil
		}
		return nil, err
	}
	return pub, nil
}

func verifyPubKey(pub any, algorithm string, digest, sig []byte) bool {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(p, digest, sig)
	case *rsa.PublicKey:
		switch strings.ToLower(algorithm) {
		case "rsa-pss-sha256":
			return rsa.VerifyPSS(p, crypto.SHA256, digest, sig,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		default:
			return rsa.VerifyPKCS1v15(p, crypto.SHA256, digest, sig) == nil
		}
	}
	return false
}

var _ = time.Time{} // keep import used (see DecisionRejected* future fields)
