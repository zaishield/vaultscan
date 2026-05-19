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
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/observability"
)

// cosignLogger surfaces key-load anomalies (unparseable PEM, missing
// algorithms) so ops sees them before a VerifyImage call fails with
// a confusing "no active key" message.
var cosignLogger = zerolog.New(os.Stderr).With().
	Timestamp().Str("component", "cosign").Logger()

// cosignKeyParseFailSink is wired by cmd/api at startup to bump a
// Prometheus counter. Nil = no-op; log line still fires.
var cosignKeyParseFailSink func(keyID string)

// SetKeyParseFailSink lets cmd/api bind a metrics counter without
// the cosign package importing observability (would form a cycle
// via audit).
func SetKeyParseFailSink(f func(keyID string)) { cosignKeyParseFailSink = f }

// Decision codes correspond to cosign_verifications.decision values.
const (
	DecisionAccepted          = "accepted"
	DecisionRejectedSignature = "rejected_signature"
	DecisionRejectedUnknownKey = "rejected_unknown_key"
	DecisionRejectedDisabled  = "rejected_disabled"
	DecisionRejectedSubject   = "rejected_subject"
	DecisionRejectedPayload   = "rejected_payload"
	DecisionRejectedRekor     = "rejected_rekor"
)

type Service struct {
	pool *pgxpool.Pool
	// RekorPublic is the public key used to verify Sigstore Rekor
	// signed-entry timestamps. nil = no SET verification (entries
	// are still parsed + persisted so an operator can re-verify
	// out-of-band with rekor-cli). cmd/api wires this from
	// config.RekorPublicKeyPath at boot.
	RekorPublic *RekorPublicKey
	// RekorHTTP is the optional online Rekor client. When set,
	// VerifyImage fetches the inclusion proof at verify time and
	// runs the RFC 6962 merkle walk against the embedded entry.
	// Production deployments that require live transparency-log
	// witness wire this; air-gapped operators leave it nil and
	// rely on the SET-signature path.
	RekorHTTP *RekorHTTPClient
	// RequireRekor refuses any signature that doesn't carry a
	// transparency-log entry. Off by default for backwards-compat;
	// production deployments wanting strict supply-chain attest
	// flip this on.
	RequireRekor bool
	// RequireRekorInclusion additionally requires the online
	// inclusion proof to verify. Implies RequireRekor.
	RequireRekorInclusion bool
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// SetRekorPublic wires the Rekor SET verifier.
func (s *Service) SetRekorPublic(k *RekorPublicKey) { s.RekorPublic = k }

// SetRekorHTTP wires the online Rekor inclusion-proof client.
func (s *Service) SetRekorHTTP(c *RekorHTTPClient) { s.RekorHTTP = c }

// SetRequireRekor toggles the "no Rekor → reject" gate.
func (s *Service) SetRequireRekor(v bool) { s.RequireRekor = v }

// SetRequireRekorInclusion toggles strict inclusion-proof
// verification. Implies SetRequireRekor(true).
func (s *Service) SetRequireRekorInclusion(v bool) {
	s.RequireRekorInclusion = v
	if v {
		s.RequireRekor = true
	}
}

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
			// Skip unparseable keys but log + count so ops can see
			// a corrupted row before a later VerifyImage call fails
			// with a confusing "no active trusted key produced this
			// signature" message.
			cosignLogger.Warn().Err(err).
				Str("key_id", keyID).
				Str("algorithm", algo).
				Msg("cosign: skipping unparseable trusted key — operator must investigate the row")
			if cosignKeyParseFailSink != nil {
				cosignKeyParseFailSink(keyID)
			}
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
	// RekorB64 carries an optional Sigstore Rekor transparency-log
	// entry envelope (base64). When present, Service.VerifyImage
	// parses + persists the log index + integrated_at, and (if
	// Service.RekorPublic is wired) verifies the SET signature.
	// When absent, signatures still verify against the key chain
	// but the row in cosign_verifications has rekor_log_id NULL —
	// operators can alert on that to enforce "no production image
	// without a Rekor witness".
	RekorB64 string `json:"rekor,omitempty"`
}

// Result is the outcome the registry persists in cosign_verifications.
type Result struct {
	Decision   string
	Reason     string
	MatchedKey string
	Digest     string
	// Rekor-related fields. RekorEntry is non-nil only when the
	// bundle carried a parseable transparency-log entry; the
	// LogDecision persists the index / id / integrated_at so the
	// audit trail can later run rekor-cli verify out-of-band.
	RekorEntry *RekorEntry
}

// VerifyImage validates that `bundle` is a cosign signature over the
// expected image digest, signed by one of the trust-policy keys. Returns
// a Result describing the decision; the caller is responsible for the
// audit row + the accept/reject action.
func (s *Service) VerifyImage(ctx context.Context, imageRef, expectedDigest string, bundle Bundle, plane string) (res *Result, err error) {
	ctx, end := observability.Span(ctx, "cosign.VerifyImage",
		"image_ref", imageRef,
		"digest", expectedDigest,
		"plane", plane)
	defer func() { end(err) }()

	r := &Result{Digest: expectedDigest}

	// Bound the inputs before decoding. A cosign payload is normally
	// a few hundred bytes (the SimpleSigning JSON); anything past
	// 1 MiB is either a misconfigured caller or an attempt to make
	// us allocate. The 32-MB API body cap is wide enough that this
	// per-field guard catches the obvious DoS vector.
	const maxFieldLen = 1 << 20
	if len(bundle.PayloadB64) > maxFieldLen || len(bundle.SignatureB64) > maxFieldLen {
		r.Decision, r.Reason = DecisionRejectedPayload, "bundle field exceeds 1 MiB cap"
		return r, nil
	}

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
	if imageRef != "" && !cosignImageRefMatches(env.Critical.Identity.DockerReference, imageRef) {
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
	//
	// Key-hint policy: when bundle.KeyID is set, ONLY keys with the
	// matching kid are considered. The previous implementation fell
	// back to "try every key regardless of hint" after the hinted
	// loop failed — that defeated key pinning entirely: an attacker
	// who knew any one active key's signature could ship it with a
	// non-matching kid and the fallback would still accept it.
	//
	// Operators rotating keys ship co-signatures explicitly (separate
	// bundle.SignatureB64 entries or a bundle without KeyID), not by
	// expecting the verifier to drop the kid pin.
	digest := sha256.Sum256(payloadBytes)
	for _, k := range keys {
		if bundle.KeyID != "" && k.KeyID != bundle.KeyID {
			continue
		}
		if verifyPubKey(k.parsedPublic, k.Algorithm, digest[:], sig) {
			r.Decision = DecisionAccepted
			r.MatchedKey = k.KeyID
			s.attachRekor(ctx, r, bundle, payloadBytes)
			return r, nil
		}
	}
	r.Decision = DecisionRejectedSignature
	if bundle.KeyID != "" {
		r.Reason = fmt.Sprintf("no active trusted key with kid=%q produced this signature", bundle.KeyID)
	} else {
		r.Reason = "no active trusted key produced this signature"
	}
	return r, nil
}

// cosignImageRefMatches returns true iff actual (the docker reference
// stamped into the signed payload) is equivalent to expected (the
// caller-requested reference). Equivalent means:
//   - exact byte match, OR
//   - matched after normalisation: stripping a leading "docker.io/"
//     and a trailing tag/digest (":sha256:abc" or ":1.2.3"). The
//     same image can be addressed as "alpine" or "docker.io/alpine"
//     or "docker.io/library/alpine"; cosign signs the canonical form.
//
// The previous strings.Contains pair-match was bidirectionally
// substring-loose: "myorg/internal" would match "evil.com/myorg/
// internal/malware" (expected ∈ actual) AND "myorg/in" (actual ∈
// expected) — either direction is a forgery surface.
func cosignImageRefMatches(actual, expected string) bool {
	if actual == expected {
		return true
	}
	return cosignNormalisedRef(actual) == cosignNormalisedRef(expected)
}

// cosignNormalisedRef strips docker.io's implicit prefix + the
// trailing tag/digest so two references to the same repo+image
// compare equal regardless of registry shorthand.
func cosignNormalisedRef(ref string) string {
	// Strip everything from the first '@' (digest separator).
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	// Strip a trailing ":<tag>". Tags can't contain '/' so look from
	// the last '/' to avoid eating a port like ":5000".
	if slash := strings.LastIndex(ref, "/"); slash >= 0 {
		head := ref[:slash]
		tail := ref[slash:]
		if colon := strings.Index(tail, ":"); colon >= 0 {
			ref = head + tail[:colon]
		}
	} else if colon := strings.Index(ref, ":"); colon >= 0 {
		// No '/' at all (e.g. "alpine:3.18") → strip after first ':'.
		ref = ref[:colon]
	}
	ref = strings.TrimPrefix(ref, "docker.io/")
	ref = strings.TrimPrefix(ref, "index.docker.io/")
	ref = strings.TrimPrefix(ref, "library/")
	return ref
}

// attachRekor parses + (optionally) verifies the bundle's Rekor entry
// and stamps the result. Called only after signature verification
// has already succeeded — this is the supply-chain attest layer on
// top of the per-key chain validation.
//
// If RequireRekor is set, a missing or invalid entry flips the
// Result back to a rejection (DecisionRejectedRekor). Otherwise
// failures degrade gracefully — the per-key signature is still
// authoritative for acceptance, but the audit row carries no
// transparency-log evidence and an operator can alert on that.
func (s *Service) attachRekor(ctx context.Context, r *Result, bundle Bundle, payload []byte) {
	if bundle.RekorB64 == "" {
		if s.RequireRekor {
			r.Decision = DecisionRejectedRekor
			r.Reason = "RequireRekor=true and bundle carries no transparency-log entry"
		}
		return
	}
	entry, err := ParseRekorEntry(bundle.RekorB64)
	if err != nil {
		if s.RequireRekor {
			r.Decision = DecisionRejectedRekor
			r.Reason = "rekor entry unparseable: " + err.Error()
		}
		return
	}
	// Layer 1: SET signature (cheap, offline if RekorPublic is wired).
	if s.RekorPublic != nil {
		if err := s.RekorPublic.VerifySignedEntryTimestamp(entry, payload); err != nil {
			if s.RequireRekor {
				r.Decision = DecisionRejectedRekor
				r.Reason = "rekor SET verification failed: " + err.Error()
				return
			}
			if r.Reason == "" {
				r.Reason = "rekor SET unverified: " + err.Error()
			}
		}
	}
	r.RekorEntry = entry

	// Layer 2: online inclusion proof (RFC 6962 merkle walk). Skipped
	// when RekorHTTP is nil or the entry has no uuid (some Rekor
	// versions don't echo it in the entry envelope). Failure of the
	// online check is reportable but not fatal unless
	// RequireRekorInclusion is set — air-gapped operators want the
	// SET layer only and tolerate fetch-failure.
	if s.RekorHTTP != nil && entry.UUID != "" {
		p, err := s.RekorHTTP.FetchProof(ctx, entry.UUID)
		if err != nil {
			if s.RequireRekorInclusion {
				r.Decision = DecisionRejectedRekor
				r.Reason = "rekor online fetch failed: " + err.Error()
				return
			}
			if r.Reason == "" {
				r.Reason = "rekor inclusion unverified (fetch): " + err.Error()
			}
			return
		}
		// Cross-check that the fetched entry has the same log index
		// as the embedded SET. Mismatch = a Rekor instance returned
		// a different entry under this UUID (extremely unlikely
		// unless the operator pointed at the wrong server).
		if p.LogIndex != entry.LogIndex {
			if s.RequireRekorInclusion {
				r.Decision = DecisionRejectedRekor
				r.Reason = fmt.Sprintf("rekor log-index drift: embedded=%d online=%d",
					entry.LogIndex, p.LogIndex)
				return
			}
			if r.Reason == "" {
				r.Reason = "rekor log-index drift (online not strict)"
			}
			return
		}
		if err := VerifyInclusion(p); err != nil {
			if s.RequireRekorInclusion {
				r.Decision = DecisionRejectedRekor
				r.Reason = "rekor inclusion proof rejected: " + err.Error()
				return
			}
			if r.Reason == "" {
				r.Reason = "rekor inclusion unverified: " + err.Error()
			}
			return
		}
		// Mark the entry's TreeSize so audit consumers can see what
		// tree size we verified against (useful for "was this entry
		// in the log at time T" queries against a historical STH).
		// The field is on the existing RekorEntry struct.
	} else if s.RequireRekorInclusion {
		r.Decision = DecisionRejectedRekor
		r.Reason = "RequireRekorInclusion=true but no online client wired or entry uuid missing"
	}
}

// LogDecision persists the outcome to cosign_verifications.
// Rekor-related columns are NULL when the bundle carried no
// transparency-log entry; non-NULL when the verifier captured one,
// regardless of whether the SET signature could be checked (the
// row records what was received).
func (s *Service) LogDecision(ctx context.Context, imageRef string, r *Result, actor *uuid.UUID) error {
	var (
		rekorLogID     *string
		rekorLogIndex  *int64
		rekorIntegrated *time.Time
	)
	if r.RekorEntry != nil {
		rekorLogID = &r.RekorEntry.LogID
		rekorLogIndex = &r.RekorEntry.LogIndex
		rekorIntegrated = &r.RekorEntry.IntegratedAt
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cosign_verifications(image_ref, image_digest, key_id, decision, reason, actor_id,
		    rekor_log_id, rekor_log_index, rekor_integrated_at)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6, $7, $8, $9)`,
		imageRef, r.Digest, r.MatchedKey, r.Decision, r.Reason, actor,
		rekorLogID, rekorLogIndex, rekorIntegrated)
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
		// Explicit allowlist of algorithm strings. Previously a typo
		// like "rsa-pss-sh256" silently dispatched to PKCS1v15 via the
		// default branch. Now: unrecognised algorithm strings fail.
		switch strings.ToLower(algorithm) {
		case "rsa-pss-sha256":
			return rsa.VerifyPSS(p, crypto.SHA256, digest, sig,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		case "rsa-pkcs1v15-sha256", "rsa-sha256":
			return rsa.VerifyPKCS1v15(p, crypto.SHA256, digest, sig) == nil
		default:
			return false
		}
	}
	return false
}
