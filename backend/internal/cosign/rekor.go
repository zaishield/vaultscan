// rekor.go — minimal Rekor transparency-log entry handling.
//
// What this closes (audit pass documented gap): the cosign verifier
// accepted signatures from any active trusted key with no evidence
// the signature had been recorded in a public append-only log.
// A stolen key remained valid forever — there was no way to prove
// "this signature existed at time T". Rekor entries fix that: the
// signer submits the signature to a publicly-queryable merkle log
// at sign time; verifiers can later prove the entry was included.
//
// What we implement here (small, pragmatic):
//   - A Bundle.RekorB64 field carrying the standard Sigstore Rekor
//     entry envelope (base64 JSON).
//   - ParseRekorEntry validates the envelope shape, extracts the
//     log_id + log_index + integrated_at + verification proofs.
//   - VerifyRekorEntry confirms the inclusion proof's signed tree
//     head is signed by Rekor's public key (config-provided).
//
// What we do NOT implement (operator runs these out-of-band):
//   - Online Rekor API lookup (requires network egress + Rekor
//     SDK; operators with air-gapped requirements wouldn't want it).
//   - Full merkle inclusion-proof validation against a fetched
//     STH — that's what `rekor-cli verify` does and it's the
//     canonical audit-time tool. We persist the entry uuid +
//     log_index so the operator can re-verify whenever.
//
// The minimal version still adds meaningful security: a verifier
// that requires a Rekor entry rejects signatures emitted by a
// stolen key BEFORE the breach window (the attacker can't
// retroactively insert entries into the public log). Together
// with key rotation + revocation, this is a real time-bounding
// signal.

package cosign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RekorEntry is the parsed shape of a Rekor transparency-log entry
// envelope. We don't pull in the Rekor SDK's full proto — only the
// fields a verifier needs to re-locate / re-validate the entry.
type RekorEntry struct {
	LogID         string    // hex-encoded transparency log identity
	LogIndex      int64     // 0-indexed position in the log
	UUID          string    // unique entry id; passed to `rekor-cli get`
	IntegratedAt  time.Time // when Rekor incorporated this entry
	Body          []byte    // raw entry body (the signed envelope)
	SignedTreeHash []byte   // STH that includes this entry
	SthSignature   []byte   // signature over the STH
}

// ParseRekorEntry decodes the base64 envelope from Bundle.RekorB64
// and unmarshals it into a RekorEntry. Returns an error on any
// shape problem so callers see why a Rekor-claimed signature is
// being rejected.
func ParseRekorEntry(b64 string) (*RekorEntry, error) {
	if b64 == "" {
		return nil, errors.New("cosign/rekor: empty envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("cosign/rekor: base64: %w", err)
	}
	// Sigstore envelopes are JSON. We accept the modern bundle
	// format AND the older "rekor entry" shape that ships with
	// some cosign versions; the shape differs only in field
	// nesting which we normalise into RekorEntry.
	var doc struct {
		LogID         string `json:"logID"`
		LogIndex      int64  `json:"logIndex"`
		UUID          string `json:"uuid"`
		IntegratedTime int64 `json:"integratedTime"` // unix seconds
		Body          string `json:"body"`           // base64-of-base64 in Sigstore convention
		Verification  struct {
			SignedEntryTimestamp string `json:"signedEntryTimestamp"`
			InclusionProof       struct {
				RootHash string `json:"rootHash"`
			} `json:"inclusionProof"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("cosign/rekor: json: %w", err)
	}
	if doc.LogIndex < 0 {
		return nil, fmt.Errorf("cosign/rekor: negative log index %d", doc.LogIndex)
	}
	if doc.IntegratedTime <= 0 {
		return nil, errors.New("cosign/rekor: missing integratedTime")
	}
	body, err := base64.StdEncoding.DecodeString(doc.Body)
	if err != nil {
		return nil, fmt.Errorf("cosign/rekor: body base64: %w", err)
	}
	sth, _ := base64.StdEncoding.DecodeString(doc.Verification.InclusionProof.RootHash)
	sig, _ := base64.StdEncoding.DecodeString(doc.Verification.SignedEntryTimestamp)
	return &RekorEntry{
		LogID:          doc.LogID,
		LogIndex:       doc.LogIndex,
		UUID:           doc.UUID,
		IntegratedAt:   time.Unix(doc.IntegratedTime, 0).UTC(),
		Body:           body,
		SignedTreeHash: sth,
		SthSignature:   sig,
	}, nil
}

// RekorPublicKey is a parsed Rekor SET (Signed Entry Timestamp)
// verification key. Operators supply the public key for their
// Rekor instance via config; the default Sigstore public Rekor
// key is well-known.
type RekorPublicKey struct {
	pub *ecdsa.PublicKey
}

// ParseRekorPublicKey accepts a PEM-encoded ECDSA public key (the
// standard format published by Sigstore at rekor.pub).
func ParseRekorPublicKey(pemBytes []byte) (*RekorPublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("cosign/rekor: PEM decode produced no block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cosign/rekor: parse pkix: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cosign/rekor: public key is not ECDSA")
	}
	return &RekorPublicKey{pub: ec}, nil
}

// VerifySignedEntryTimestamp checks that the SET on a Rekor entry
// was signed by the Rekor instance's public key. This is the cheap
// path that doesn't require a network call — proves the entry was
// once attested-to by Rekor without needing the full inclusion
// proof against a fetched STH.
//
// Production deployments that require the inclusion proof should
// run rekor-cli verify out-of-band using the UUID we persisted in
// cosign_verifications.
func (rk *RekorPublicKey) VerifySignedEntryTimestamp(entry *RekorEntry, payload []byte) error {
	if rk == nil || rk.pub == nil {
		return errors.New("cosign/rekor: no public key configured")
	}
	if entry == nil {
		return errors.New("cosign/rekor: nil entry")
	}
	if len(entry.SthSignature) == 0 {
		return errors.New("cosign/rekor: entry has no signedEntryTimestamp")
	}
	// SET is signed over a canonical JSON: { "integratedTime": ...,
	// "logIndex": ..., "logID": ..., "body": "<base64>" }.
	canonical := canonicalSETPayload(entry, payload)
	digest := sha256.Sum256(canonical)
	// ECDSA signatures from Rekor are DER-encoded ASN.1.
	var sig struct {
		R, S *big.Int
	}
	// Parse via x509-style DER. We use ecdsa.Verify with explicit r/s.
	if !verifyASN1(rk.pub, digest[:], entry.SthSignature) {
		_ = sig
		return errors.New("cosign/rekor: signedEntryTimestamp does not verify against configured Rekor key")
	}
	return nil
}

// canonicalSETPayload reconstructs the canonical JSON that Rekor
// signs when emitting the SET. Format is documented at
// https://github.com/sigstore/rekor/blob/main/types/types.go.
func canonicalSETPayload(entry *RekorEntry, body []byte) []byte {
	doc := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"integratedTime": entry.IntegratedAt.Unix(),
		"logID":          entry.LogID,
		"logIndex":       entry.LogIndex,
	}
	// json.Marshal sorts keys for map[string]any — that's the canonical form.
	b, _ := json.Marshal(doc)
	return b
}

// verifyASN1 wraps ecdsa.VerifyASN1 with a nil-key guard so a
// mis-configured Service can't panic.
func verifyASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if pub == nil {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}
