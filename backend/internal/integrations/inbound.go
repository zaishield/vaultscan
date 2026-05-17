// inbound.go — inbound webhook signature verification framework.
//
// Many integrations (Slack interactivity, GitHub Apps, Jira, custom
// partner webhooks) call BACK into our API to deliver events.
// Without HMAC verification these endpoints are open relays for
// spoofed events — anyone with the URL can post arbitrary state
// transitions.
//
// This module implements the standard pattern shared by all of those
// providers:
//
//  1. Each integration has a shared secret stored in
//     integration_settings.signing_secret (encrypted at rest by the
//     evidence vault DEK; see migration that adds the column).
//
//  2. On every callback POST the caller computes:
//
//	HMAC-SHA256(secret, "<timestamp>." || body)
//
//     and sends it in two headers: X-VaultScan-Timestamp + the
//     signature header (default X-VaultScan-Signature, configurable
//     per provider). Some providers use t=...,v1=... (Stripe-style);
//     this module supports that form too via ParseStripe.
//
//  3. We compare with hmac.Equal (constant-time) and reject any
//     timestamp older than `tolerance` (default 5 min) to bound the
//     replay window.
//
// The verifier is provider-agnostic. Per-integration handlers wrap
// it with the provider's specific header names + secret lookup.
package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrSignatureMismatch indicates the computed HMAC does not match
// the supplied signature. Always rejected with 401 by handlers.
var ErrSignatureMismatch = errors.New("integrations: signature mismatch")

// ErrTimestampSkew indicates the supplied timestamp is outside the
// tolerance window — likely a replay of an old payload.
var ErrTimestampSkew = errors.New("integrations: timestamp outside tolerance window")

// ErrMissingSignature indicates the request lacks the signature
// header. Returned as a separate error so the handler can log
// "client misconfigured" vs "tampering attempt" distinctly.
var ErrMissingSignature = errors.New("integrations: missing signature header")

// VerifyOptions configures the signature verifier. Zero values use
// safe defaults (HMAC-SHA256, 5-minute tolerance).
type VerifyOptions struct {
	// Tolerance is the maximum |now - timestamp| we accept.
	// Default 5 minutes — matches Slack / Stripe / GitHub.
	Tolerance time.Duration

	// Now returns the current time; injectable for tests.
	Now func() time.Time
}

// Verify checks that signatureHex is the HMAC-SHA256 of
// "<timestamp>.<body>" under `secret`. The timestamp is parsed as a
// Unix epoch second.
//
// Returns nil on success; one of the typed errors above on failure.
// Internal errors (parse failures) are wrapped as
// "integrations: invalid input: ...".
func Verify(secret string, timestamp string, body []byte, signatureHex string, opts VerifyOptions) error {
	if signatureHex == "" {
		return ErrMissingSignature
	}
	if opts.Tolerance == 0 {
		opts.Tolerance = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	tsInt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("integrations: invalid input: timestamp: %w", err)
	}
	ts := time.Unix(tsInt, 0)
	delta := opts.Now().Sub(ts)
	if delta < 0 {
		delta = -delta
	}
	if delta > opts.Tolerance {
		return ErrTimestampSkew
	}

	supplied, err := hex.DecodeString(strings.TrimPrefix(signatureHex, "sha256="))
	if err != nil {
		return fmt.Errorf("integrations: invalid input: signature: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, supplied) {
		return ErrSignatureMismatch
	}
	return nil
}

// ParseStripe extracts (timestamp, signature) from the Stripe-style
// header value `t=1492774577,v1=hex,v0=hex`. Returns "", "" if the
// expected fields are missing — callers should treat that as
// ErrMissingSignature.
func ParseStripe(header string) (timestamp, signature string) {
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signature = kv[1]
		}
	}
	return
}
