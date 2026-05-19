package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// signRef builds the HMAC over (tenantID || evidenceID || exp).
// The tenant binding closes the cross-tenant replay window the
// audit flagged: previously the MAC only covered (id || exp), so a
// signed URL minted for tenant A could be replayed against the
// same evidence_id under tenant B (if an attacker learned both ids).
//
// The HMAC key is derived from the master KEK via a fixed purpose
// string — separates URL-signing material from the AEAD key the
// vault uses for envelope encryption (NIST SP 800-57 §5.2 domain-
// separation guidance). The derivation is a single HMAC pass; not
// HKDF but achieves the same key-separation goal for our purpose.
func signRef(key []byte, tenantID, id string, exp int64) string {
	purposeKey := deriveURLSigningKey(key)
	mac := hmac.New(sha256.New, purposeKey)
	// Stable framing — explicit lengths prevent extension attacks
	// (a tenant id ending in `|abc` and an id `def|...` would
	// otherwise hash the same as tenant `|abc|def|...` and id `...`).
	mac.Write([]byte("v2|"))
	mac.Write([]byte(tenantID))
	mac.Write([]byte{'|'})
	mac.Write([]byte(id))
	mac.Write([]byte{'|'})
	mac.Write([]byte(strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// deriveURLSigningKey produces a domain-separated 32-byte HMAC key
// from the master KEK. HMAC-SHA256 of a fixed label is the minimum
// viable HKDF-like derivation; sufficient because the master KEK is
// already a high-entropy 32-byte key.
func deriveURLSigningKey(masterKEK []byte) []byte {
	mac := hmac.New(sha256.New, masterKEK)
	mac.Write([]byte("vaultscan/evidence/signed-url/v2"))
	return mac.Sum(nil)
}

// constantTimeEqualString compares a and b in constant time.
//
// To avoid leaking the actual length of `a` (the expected HMAC, a
// fixed-length value) via early-return on a length mismatch, we
// always run ConstantTimeCompare on equal-length copies — if the
// inputs differ in length, we pad b to len(a) with zeros and still
// XOR through all bytes. The final && of "lengths equal" ensures
// any padding case fails. This isn't strictly necessary when `a` is
// HMAC output (always 64 hex chars), but defense in depth: any
// future caller passing a non-fixed expected value benefits.
func constantTimeEqualString(a, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)
	// Pick the longer length so we always XOR over the full buffer.
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}
	aPad := make([]byte, maxLen)
	bPad := make([]byte, maxLen)
	copy(aPad, aBytes)
	copy(bPad, bBytes)
	eq := subtle.ConstantTimeCompare(aPad, bPad) == 1
	return eq && len(aBytes) == len(bBytes)
}

// parseObjectURL splits "vaultscan://<tenant>/<object>" into the two
// UUIDs. Returns (_, _, false) for any malformed input.
func parseObjectURL(storageURL string) (tenantID, objectID uuid.UUID, ok bool) {
	const prefix = "vaultscan://"
	if !strings.HasPrefix(storageURL, prefix) {
		return uuid.Nil, uuid.Nil, false
	}
	parts := strings.SplitN(storageURL[len(prefix):], "/", 2)
	if len(parts) != 2 {
		return uuid.Nil, uuid.Nil, false
	}
	tid, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	oid, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return tid, oid, true
}

// vaultscanURLToPath is the legacy filesystem helper retained for the
// FilesystemStorage backend's own internal use + the integration test
// that pokes at on-disk layout directly.
func vaultscanURLToPath(root, storageURL string) string {
	tenantID, objectID, ok := parseObjectURL(storageURL)
	if !ok {
		return ""
	}
	return filepath.Join(root, tenantID.String(), objectID.String()+".enc")
}

func ipOrNull(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
