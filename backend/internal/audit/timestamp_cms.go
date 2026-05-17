// timestamp_cms.go — full CMS SignedData signature verification for
// RFC 3161 timestamp tokens.
//
// Closes the documented gap: previously TSAClient.VerifyChain only
// validated the cert chain but did not verify that the SignerInfo
// signature inside the CMS was actually produced by the leaf's
// private key. A stolen timestamping cert chaining to a trusted
// root could therefore still mint a passing token.
//
// What full CMS verification adds:
//   1. Parse SignedData.signerInfos[0].
//   2. Read the signed attributes (RFC 5652 §5.3) — these include
//      messageDigest (sha256 of TSTInfo) and contentType.
//   3. Verify messageDigest matches the actual sha256(eContent).
//   4. Re-encode signed-attributes as universal SET-OF (RFC 5652
//      §5.4 — the signature is computed over the SET tag, not the
//      IMPLICIT [0] tag used in transit).
//   5. Verify SignerInfo.signature against (algo, leaf pubkey,
//      hash(re-encoded SignedAttrs)).
//
// The cert chain validation in timestamp.go now calls into this
// after Verify() succeeds. Together they close the MitM gap: an
// attacker with a token NOT signed by the embedded leaf's private
// key is rejected; an attacker with the leaf's private key needs
// to have stolen it from a CA in TrustedRoots.

package audit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
)

// VerifyCMSSignature checks that the CMS SignedData token was signed
// by the embedded leaf cert. Returns nil on a valid signature.
//
// This is intentionally narrow: we accept the single-signer case
// (Rekor / RFC 3161 TSAs never emit multiple signers in a
// timestamp response). RSA-PKCS#1 v1.5 and ECDSA signatures are
// supported with SHA-256 / SHA-384 / SHA-512 digests.
func VerifyCMSSignature(cmsDER []byte, leaf *x509.Certificate) error {
	if leaf == nil {
		return errors.New("rfc3161: nil leaf cert")
	}
	si, err := extractSignerInfo(cmsDER)
	if err != nil {
		return fmt.Errorf("rfc3161: extract SignerInfo: %w", err)
	}
	// (1) verify messageDigest attribute against actual eContent hash.
	if err := verifyMessageDigest(cmsDER, si); err != nil {
		return err
	}
	// (2) Re-encode signedAttrs with the universal SET tag for
	// signature verification. RFC 5652 §5.4: "A separate encoding of
	// the signedAttrs field is performed for message digest
	// calculation. The IMPLICIT [0] tag in the signedAttrs is not
	// used for the DER encoding; rather, an EXPLICIT SET OF tag is
	// used. That is, the DER encoding of the EXPLICIT SET OF tag,
	// rather than of the IMPLICIT [0] tag, MUST be included in the
	// message digest calculation along with the length and content
	// octets of the SignedAttributes value."
	canonAttrs, err := canonicalSignedAttrs(si.RawSignedAttrs.FullBytes)
	if err != nil {
		return fmt.Errorf("rfc3161: canonicalise signedAttrs: %w", err)
	}
	// (3) hash + verify.
	h, hashAlgo, err := newHashForOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	h.Write(canonAttrs)
	digest := h.Sum(nil)
	return verifySignatureWithLeaf(leaf, hashAlgo, digest, si.Signature,
		si.SignatureAlgorithm.Algorithm)
}

// signerInfo is the parsed SignerInfo shape we care about. We use
// asn1.RawValue for the signed-attrs field because the DER-encoded
// bytes (with the original IMPLICIT [0] tag) are needed downstream
// to re-canonicalise into the universal SET form for hashing.
type signerInfo struct {
	Version            int
	SID                asn1.RawValue // issuerAndSerialNumber OR subjectKeyIdentifier
	DigestAlgorithm    pkixAlgorithmIdentifier
	RawSignedAttrs     asn1.RawValue `asn1:"tag:0,implicit,optional"`
	SignatureAlgorithm pkixAlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"tag:1,implicit,optional"`
}

// pkixAlgorithmIdentifier is a copy of crypto/x509/pkix.AlgorithmIdentifier
// re-declared here so this file doesn't need the pkix import (timestamp.go
// already imports it; consolidation would just split the same code).
type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// extractSignerInfo walks the CMS down to SignedData.signerInfos[0].
// Returns an error if the CMS is missing the SignerInfo entirely or
// contains multiple signers (timestamp tokens always have exactly one).
func extractSignerInfo(cmsDER []byte) (*signerInfo, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	var sd struct {
		Version          int
		DigestAlgs       asn1.RawValue `asn1:"set"`
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"tag:0,implicit,optional"`
		CRLs             asn1.RawValue `asn1:"tag:1,implicit,optional"`
		SignerInfos      asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	// SignerInfos is SET OF SignerInfo — iterate.
	var sis []signerInfo
	rest := sd.SignerInfos.Bytes
	for len(rest) > 0 {
		var si signerInfo
		var err error
		rest, err = asn1.Unmarshal(rest, &si)
		if err != nil {
			return nil, fmt.Errorf("SignerInfo: %w", err)
		}
		sis = append(sis, si)
	}
	if len(sis) == 0 {
		return nil, errors.New("no SignerInfo in SignedData")
	}
	if len(sis) > 1 {
		// Timestamp tokens always have a single signer; reject the
		// multi-signer case rather than guess which one to trust.
		return nil, fmt.Errorf("expected 1 SignerInfo, got %d", len(sis))
	}
	return &sis[0], nil
}

// verifyMessageDigest confirms the messageDigest attribute equals the
// actual sha256 of the encapsulated TSTInfo bytes. This is the link
// between "what the SignerInfo signed" and "what content the token
// claims to attest". An attacker who substituted the eContent
// (changing the timestamp serial or generalised time) but kept the
// original SignerInfo would fail this check.
func verifyMessageDigest(cmsDER []byte, si *signerInfo) error {
	// Re-parse just enough to get eContent.
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		return err
	}
	var sd struct {
		Version          int
		DigestAlgs       asn1.RawValue `asn1:"set"`
		EncapContentInfo struct {
			ContentType asn1.ObjectIdentifier
			EContent    asn1.RawValue `asn1:"tag:0,explicit,optional"`
		}
		Rest asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return err
	}
	if len(sd.EncapContentInfo.EContent.Bytes) == 0 {
		return errors.New("encapContentInfo has no eContent (detached signatures not supported)")
	}
	// EContent is OCTET STRING containing the TSTInfo DER. Unwrap.
	var inner []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &inner); err != nil {
		return fmt.Errorf("eContent OCTET STRING: %w", err)
	}
	wantHash, hashAlgo, err := newHashForOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	_ = hashAlgo
	wantHash.Write(inner)
	want := wantHash.Sum(nil)

	// Find messageDigest in signedAttrs.
	got, err := findMessageDigestAttr(si.RawSignedAttrs.Bytes)
	if err != nil {
		return err
	}
	if !bytesEqual(got, want) {
		return errors.New("messageDigest attribute does not match sha256(eContent)")
	}
	return nil
}

// findMessageDigestAttr scans the signedAttrs SET for the
// messageDigest attribute (OID 1.2.840.113549.1.9.4) and returns the
// digest bytes.
func findMessageDigestAttr(attrsBytes []byte) ([]byte, error) {
	oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	rest := attrsBytes
	for len(rest) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil, fmt.Errorf("attribute: %w", err)
		}
		if attr.Type.Equal(oidMessageDigest) {
			// Values is SET OF OCTET STRING; we want the single
			// OCTET STRING inside.
			var digest []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &digest); err != nil {
				return nil, fmt.Errorf("messageDigest OCTET STRING: %w", err)
			}
			return digest, nil
		}
	}
	return nil, errors.New("messageDigest attribute not found in signedAttrs")
}

// canonicalSignedAttrs takes the raw signedAttrs bytes (with the
// transit-form IMPLICIT [0] tag) and re-encodes them as universal
// SET-OF — the form signatures are computed over. RFC 5652 §5.4.
//
// In practice this means swapping the first byte (the tag) from
// 0xA0 (CONTEXT-SPECIFIC, constructed, 0) to 0x31 (UNIVERSAL,
// constructed, SET = tag 17 = 0x11 | 0x20). The length bytes and
// content are unchanged.
func canonicalSignedAttrs(implicit []byte) ([]byte, error) {
	if len(implicit) < 2 {
		return nil, errors.New("signedAttrs too short (need tag + at least one length byte)")
	}
	if implicit[0] != 0xA0 {
		// Not the IMPLICIT [0] form we expected. Could be that the
		// caller already passed us the universal form (some test
		// harnesses do); accept it if so, reject otherwise.
		if implicit[0] == 0x31 {
			return implicit, nil
		}
		return nil, fmt.Errorf("unexpected signedAttrs tag 0x%02x", implicit[0])
	}
	// Validate the length encoding before swapping the tag. Long-form
	// lengths (first length byte has high bit set, e.g. 0x81/0x82/...)
	// are legal DER and we MUST handle them correctly — only the
	// FIRST byte (tag) is being swapped, the length octets that
	// follow are untouched. Without this check a malformed input
	// with a truncated length would pass through silently.
	lenByte := implicit[1]
	if lenByte&0x80 != 0 {
		// Long-form: low 7 bits = number of subsequent length octets.
		nLen := int(lenByte & 0x7F)
		if nLen == 0 || nLen > 4 {
			// 0 = indefinite (BER, not DER); >4 = absurdly large.
			return nil, fmt.Errorf("signedAttrs has invalid long-form length octet count %d", nLen)
		}
		if len(implicit) < 2+nLen {
			return nil, errors.New("signedAttrs truncated before length octets complete")
		}
	}
	out := make([]byte, len(implicit))
	copy(out, implicit)
	out[0] = 0x31
	return out, nil
}

// newHashForOID returns a new hash.Hash for the given digest OID
// plus the matching crypto.Hash enum (for rsa.VerifyPKCS1v15).
func newHashForOID(oid asn1.ObjectIdentifier) (hash.Hash, crypto.Hash, error) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}):
		return sha256.New(), crypto.SHA256, nil
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}):
		return sha512.New384(), crypto.SHA384, nil
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}):
		return sha512.New(), crypto.SHA512, nil
	}
	return nil, 0, fmt.Errorf("unsupported digest OID %s", oid)
}

// verifySignatureWithLeaf dispatches RSA-PKCS1v15 / RSA-PSS / ECDSA
// based on the SignatureAlgorithm OID. The leaf's PublicKey must be
// the matching key type — leaves emitted by real TSAs always have
// this aligned with the signature.
func verifySignatureWithLeaf(leaf *x509.Certificate, hashAlgo crypto.Hash,
	digest, signature []byte, sigOID asn1.ObjectIdentifier) error {
	// PKCS#1 v1.5 signature OIDs (e.g. sha256WithRSAEncryption).
	rsaPKCS1 := map[string]bool{
		"1.2.840.113549.1.1.11": true, // sha256WithRSAEncryption
		"1.2.840.113549.1.1.12": true, // sha384WithRSAEncryption
		"1.2.840.113549.1.1.13": true, // sha512WithRSAEncryption
	}
	// ECDSA signature OIDs.
	ecdsaWith := map[string]bool{
		"1.2.840.10045.4.3.2": true, // ecdsa-with-SHA256
		"1.2.840.10045.4.3.3": true, // ecdsa-with-SHA384
		"1.2.840.10045.4.3.4": true, // ecdsa-with-SHA512
	}
	switch {
	case rsaPKCS1[sigOID.String()]:
		rsaKey, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("leaf cert has non-RSA key for RSA signature")
		}
		return rsa.VerifyPKCS1v15(rsaKey, hashAlgo, digest, signature)
	case ecdsaWith[sigOID.String()]:
		ecKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("leaf cert has non-ECDSA key for ECDSA signature")
		}
		if !ecdsa.VerifyASN1(ecKey, digest, signature) {
			return errors.New("ECDSA signature does not verify against leaf public key")
		}
		return nil
	}
	return fmt.Errorf("unsupported signature OID %s", sigOID)
}

// bytesEqual is a tiny stand-in for bytes.Equal — kept local so this
// file's import set stays small.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
