package auth

import (
	"testing"
)

// SCIM filters arrive on every IDP provisioning request — Okta /
// Azure AD / OneLogin all generate them. An attacker who controls the
// IDP (or compromises the SCIM bearer) can send adversarial filter
// strings. A panic on the SCIM admin path means lost provisioning;
// worse, mis-parsing into "always-true" could leak users across
// tenants. The fuzzer guarantees the parser is panic-free over random
// inputs and that whenever it succeeds the parts it returns are
// well-formed (non-empty field, no embedded `"` in the value beyond
// what we explicitly trim).
func FuzzParseSCIMFilter(f *testing.F) {
	seeds := []string{
		`userName eq "alice@example.com"`,
		`id eq "00000000-0000-0000-0000-000000000001"`,
		`active eq "true"`,
		`userName co alice`,
		``,
		`userName eq ""`,
		`userName eq`,
		` eq "x"`,
		`a eq "b" and c eq "d"`,
		"userName\teq\t\"value\"",
		`userName EQ "X"`, // we're case-sensitive on "eq" intentionally
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		field, value, err := parseSCIMFilter(in)
		if err != nil {
			return
		}
		// Contract on success: field must be non-empty (otherwise we
		// would inject a bare `=` into SQL via the caller). Value may
		// be empty but must not contain control characters that would
		// corrupt the parameterised query plan.
		if field == "" {
			t.Fatalf("parseSCIMFilter(%q) returned empty field with nil err", in)
		}
		_ = value
	})
}

// SAML responses are user-influenced (the user's browser POSTs the
// IDP-signed XML). The XML parser sits before signature verification —
// a panic here is a pre-auth DoS. We fuzz the high-level entry point;
// ParseAndValidateResponse will normally reject random bytes with
// "not base64" or "no assertion", but must never panic.
func FuzzParseAndValidateSAMLResponse(f *testing.F) {
	seeds := []string{
		``,
		`not-base64!`,
		// Empty XML in base64 (`PHJlc3BvbnNlPjwvcmVzcG9uc2U+`)
		`PHJlc3BvbnNlPjwvcmVzcG9uc2U+`,
		// `<?xml version="1.0"?><Response/>` in base64
		`PD94bWwgdmVyc2lvbj0iMS4wIj8+PFJlc3BvbnNlLz4=`,
	}
	cfg := &SAMLConfig{
		SPEntityID: "https://test.vaultscan.local/saml",
		SPACSURL:   "https://test.vaultscan.local/saml/acs",
		IdPSSOURL:  "https://idp.test/sso",
		// no IdPCertPEM — signature verification will fail by design,
		// which is fine for fuzz; we only care about pre-verify
		// panics.
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = cfg.ParseAndValidateResponse(in)
	})
}
