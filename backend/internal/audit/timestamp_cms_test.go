package audit

import (
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"testing"
)

// canonicalSignedAttrs flips the leading 0xA0 (IMPLICIT [0]) tag to
// 0x31 (universal SET). This is the critical transform RFC 5652 §5.4
// mandates before computing the signed-attrs hash — get it wrong
// and signature verification fails universally.
func TestCanonicalSignedAttrs_FlipsImplicitToUniversal(t *testing.T) {
	t.Parallel()
	// Build a synthetic IMPLICIT [0] form: 0xA0 LEN content.
	input := []byte{0xA0, 0x04, 0x01, 0x02, 0x03, 0x04}
	out, err := canonicalSignedAttrs(input)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != 0x31 {
		t.Errorf("first byte = 0x%02x, want 0x31 (universal SET)", out[0])
	}
	// Length + content must be untouched.
	if !bytesEqual(out[1:], input[1:]) {
		t.Errorf("body altered during tag swap")
	}
}

func TestCanonicalSignedAttrs_AcceptsAlreadyUniversal(t *testing.T) {
	t.Parallel()
	input := []byte{0x31, 0x04, 0x01, 0x02, 0x03, 0x04}
	out, err := canonicalSignedAttrs(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(out, input) {
		t.Errorf("universal SET should pass through unchanged")
	}
}

func TestCanonicalSignedAttrs_RejectsUnknownTag(t *testing.T) {
	t.Parallel()
	input := []byte{0x30, 0x04, 0x01, 0x02, 0x03, 0x04} // SEQUENCE — wrong
	if _, err := canonicalSignedAttrs(input); err == nil {
		t.Error("expected error for non-SET tag")
	}
}

func TestCanonicalSignedAttrs_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := canonicalSignedAttrs(nil); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestNewHashForOID_Sha256(t *testing.T) {
	t.Parallel()
	h, ch, err := newHashForOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	if err != nil {
		t.Fatal(err)
	}
	if ch != crypto.SHA256 {
		t.Errorf("ch=%v want SHA256", ch)
	}
	// Spot-check the hash works.
	h.Write([]byte("abc"))
	got := h.Sum(nil)
	want := sha256.Sum256([]byte("abc"))
	if !bytesEqual(got, want[:]) {
		t.Errorf("hash mismatch")
	}
}

func TestNewHashForOID_Sha384AndSha512(t *testing.T) {
	t.Parallel()
	for _, oid := range []asn1.ObjectIdentifier{
		{2, 16, 840, 1, 101, 3, 4, 2, 2},
		{2, 16, 840, 1, 101, 3, 4, 2, 3},
	} {
		if _, _, err := newHashForOID(oid); err != nil {
			t.Errorf("unsupported OID %s: %v", oid, err)
		}
	}
}

func TestNewHashForOID_RejectsUnknown(t *testing.T) {
	t.Parallel()
	_, _, err := newHashForOID(asn1.ObjectIdentifier{1, 2, 3, 4, 5})
	if err == nil {
		t.Error("expected error for unknown OID")
	}
}

// extractSignerInfo on garbage input must return an error, not panic.
func TestExtractSignerInfo_RejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := extractSignerInfo([]byte{0x00, 0x00}); err == nil {
		t.Error("expected error on garbage CMS input")
	}
	if _, err := extractSignerInfo(nil); err == nil {
		t.Error("expected error on nil CMS input")
	}
}

// VerifyCMSSignature with a nil leaf must reject (defence vs caller
// passing a fresh-zero *x509.Certificate).
func TestVerifyCMSSignature_RejectsNilLeaf(t *testing.T) {
	t.Parallel()
	if err := VerifyCMSSignature([]byte{0x30, 0x00}, nil); err == nil {
		t.Error("expected error for nil leaf")
	}
}

// findMessageDigestAttr happy path: builds a minimal signedAttrs
// containing a messageDigest and asserts we recover the digest bytes.
func TestFindMessageDigestAttr_RecoversDigest(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	// Build SET { Attribute { type=messageDigest, values=SET { OCTET STRING digest } } }.
	oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	digestDER, err := asn1.Marshal(digest)
	if err != nil {
		t.Fatal(err)
	}
	// Values is SET OF (universal SET) containing one OCTET STRING.
	valuesSet := []byte{0x31, byte(len(digestDER))}
	valuesSet = append(valuesSet, digestDER...)
	// Attribute = SEQUENCE { OID, valuesSet }.
	oidDER, _ := asn1.Marshal(oidMessageDigest)
	attrInner := append([]byte{}, oidDER...)
	attrInner = append(attrInner, valuesSet...)
	attrDER := append([]byte{0x30, byte(len(attrInner))}, attrInner...)
	// findMessageDigestAttr expects "attribute set contents" — i.e.
	// the concatenation of attribute DERs, without an outer SET tag.
	got, err := findMessageDigestAttr(attrDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(got, digest) {
		t.Errorf("recovered digest mismatch")
	}
}

func TestFindMessageDigestAttr_MissingAttrErrors(t *testing.T) {
	t.Parallel()
	if _, err := findMessageDigestAttr(nil); err == nil {
		t.Error("expected error when messageDigest attr missing")
	}
}
