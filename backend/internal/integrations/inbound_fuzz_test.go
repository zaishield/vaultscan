package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// FuzzVerifyInbound exercises the HMAC verifier with attacker-
// controlled inputs across every parameter:
//   * timestamp string (parsed via strconv.ParseInt)
//   * body bytes (any size, any content)
//   * signature header value (hex with optional sha256= prefix)
//
// The threat model is an external system sending malformed
// webhooks. None of these inputs may cause a panic, and a valid
// signature MUST never appear where one wasn't computed.
func FuzzVerifyInbound(f *testing.F) {
	// Seed with the cross-product of "valid signature for this body"
	// and "deliberately broken" cases.
	seeds := []struct {
		ts, sig string
		body    string
	}{
		{"1700000000", "sha256=invalid", "hello"},
		{"not-a-number", "sha256=AAAA", ""},
		{"", "", ""},
		{"1700000000", "", "x"},
		{"1700000000", "sha256=" + strRepeat("aa", 32), "y"}, // valid hex, wrong digest
		{"-9223372036854775808", "AA", "boundary-min"},
		{"9223372036854775807", "AA", "boundary-max"},
		{"99999999999999999999", "AA", "overflow"},
		{"1700000000", "not_hex!!", "bad-hex"},
		{"1700000000", "sha256=AABB", "short-sig"},
	}
	for _, s := range seeds {
		f.Add(s.ts, s.sig, []byte(s.body))
	}

	fixedNow := time.Unix(1700000000, 0)
	opts := VerifyOptions{
		Tolerance: 5 * time.Minute,
		Now:       func() time.Time { return fixedNow },
	}

	f.Fuzz(func(t *testing.T, ts, sigHex string, body []byte) {
		// Cap to keep the fuzzer's allocation footprint sane.
		if len(body) > 1<<20 || len(sigHex) > 1024 || len(ts) > 64 {
			t.Skip()
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify PANICKED ts=%q sig=%q body_len=%d: %v",
					ts, sigHex, len(body), r)
			}
		}()
		// Just exercising the parser/verifier — the test secret
		// won't match any attacker-controllable signature.
		err := Verify("test-secret", ts, body, sigHex, opts)
		if err == nil {
			// If err is nil, the signature MUST validate against
			// "test-secret". Recompute and compare.
			mac := hmac.New(sha256.New, []byte("test-secret"))
			_, _ = mac.Write([]byte(ts))
			_, _ = mac.Write([]byte{'.'})
			_, _ = mac.Write(body)
			expected := mac.Sum(nil)
			// Strip optional prefix
			s := sigHex
			if len(s) > 7 && s[:7] == "sha256=" {
				s = s[7:]
			}
			supplied, herr := hex.DecodeString(s)
			if herr != nil {
				t.Fatalf("SIGNATURE FORGERY: Verify accepted non-hex signature %q", sigHex)
			}
			if !hmac.Equal(expected, supplied) {
				t.Fatalf("SIGNATURE FORGERY: Verify accepted sig=%q for ts=%q body_len=%d but HMAC doesn't match",
					sigHex, ts, len(body))
			}
		}
	})
}

func strRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// FuzzParseStripe exercises the Stripe-style header parser. The
// header value comes straight from an external request; parser
// crashes here would DoS the inbound endpoint.
func FuzzParseStripe(f *testing.F) {
	seeds := []string{
		"t=1492774577,v1=AABB,v0=CCDD",
		"v1=AABB",
		"",
		",,,",
		"t=,v1=",
		"t=abc,v1=xyz",
		"t=1=2=3,v1=4=5=6",
		"   t=1, v1=  AAAA  ",
		fmt.Sprintf("t=%s,v1=%s", strRepeat("9", 50), strRepeat("a", 200)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, header string) {
		if len(header) > 4096 {
			t.Skip()
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseStripe PANICKED on %q: %v", header, r)
			}
		}()
		_, _ = ParseStripe(header)
	})
}
