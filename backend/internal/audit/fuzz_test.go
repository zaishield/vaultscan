package audit

import (
	"testing"
)

// RFC 3161 TSA responses arrive over HTTP from a third party. An
// attacker who can MitM the TSA (or pose as one in a misconfigured
// deployment) can return arbitrary ASN.1 bytes. parseTSResp must
// reject them safely — never panic, never spin, never leak memory.
//
// extractTSTInfo already has a `defer recover()` for ASN.1 surprises;
// this fuzzer proves the wider path (parseTSResp → asn1.Unmarshal →
// extractTSTInfo) is panic-free for arbitrary inputs.
func FuzzParseTSResp(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{0x30, 0x00},                  // empty SEQUENCE
		{0x30, 0x03, 0x02, 0x01, 0x00}, // tiny SEQUENCE { INTEGER 0 }
		// valid-shape but garbage trailing bytes
		{0x30, 0x05, 0x02, 0x01, 0x00, 0xFF, 0xFF},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseTSResp(raw)
	})
}

// FuzzExtractTSTInfo exercises the CMS unwrapper directly. This is the
// path most likely to encounter adversarial ASN.1 shapes (it walks
// nested SEQUENCEs and OCTET STRINGs by hand).
func FuzzExtractTSTInfo(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{0x30, 0x00},
		{0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}, // bare OCTET STRING
		{0x30, 0x06, 0x06, 0x04, 0x2A, 0x86, 0x48, 0x86}, // SEQUENCE w/ OID
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = extractTSTInfo(raw)
	})
}
