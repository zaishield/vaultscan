package findings

import (
	"testing"
	"testing/quick"

	"github.com/google/uuid"
)

// Property-based tests for the dedup fingerprint. The contract:
//   * stable: identical inputs → identical fingerprint
//   * sensitive: changing any input field → changes the fingerprint
//   * non-empty: every input produces a non-empty hex string
//
// Fuzz catches panics; quick.Check exercises hundreds of randomised
// inputs to surface accidental collisions.

func TestProperty_DedupFingerprint_Stable(t *testing.T) {
	t.Parallel()
	f := func(title, scanner, endpoint, cve, cwe, proto, sev string, port uint16) bool {
		in := IngestInput{
			PlatformID:       uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
			PartnerID:        uuid.MustParse("00000000-0000-0000-0000-0000000000b1"),
			TenantID:         uuid.MustParse("00000000-0000-0000-0000-0000000000c1"),
			EngagementID:     uuid.MustParse("00000000-0000-0000-0000-0000000000d1"),
			Title:            title, Scanner: scanner, AffectedEndpoint: endpoint,
			CVE: cve, CWE: cwe, Port: int(port), Protocol: proto, Severity: sev,
		}
		a := dedupFingerprint(in)
		b := dedupFingerprint(in)
		return a == b && len(a) == 64 // sha256 hex = 64
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestProperty_DedupFingerprint_SensitiveToTitle(t *testing.T) {
	t.Parallel()
	f := func(a, b string) bool {
		if a == b {
			return true // skip equal-input edge case
		}
		// Compare titles after lower-casing (the fingerprint does too)
		if eq := equalFold(a, b); eq {
			return true // would collide by design
		}
		base := IngestInput{
			PlatformID: uuid.New(), PartnerID: uuid.New(),
			TenantID: uuid.New(), EngagementID: uuid.New(),
			Scanner: "nmap", AffectedEndpoint: "x", Severity: "low",
		}
		base.Title = a
		fpA := dedupFingerprint(base)
		base.Title = b
		fpB := dedupFingerprint(base)
		return fpA != fpB
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	toLower := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + ('a' - 'A')
		}
		return c
	}
	for i := 0; i < len(a); i++ {
		if toLower(a[i]) != toLower(b[i]) {
			return false
		}
	}
	return true
}

func TestProperty_DedupFingerprint_SensitiveToPort(t *testing.T) {
	t.Parallel()
	f := func(p1, p2 uint16) bool {
		if p1 == p2 {
			return true
		}
		base := IngestInput{
			PlatformID: uuid.New(), PartnerID: uuid.New(),
			TenantID: uuid.New(), EngagementID: uuid.New(),
			Title: "x", Scanner: "nmap", AffectedEndpoint: "y", Severity: "low",
		}
		base.Port = int(p1)
		fpA := dedupFingerprint(base)
		base.Port = int(p2)
		fpB := dedupFingerprint(base)
		return fpA != fpB
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}
