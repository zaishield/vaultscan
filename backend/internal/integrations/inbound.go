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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/observability"
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

// SecretUnwrapper is the contract the service uses to decrypt the
// stored signing secret. evidence.Vault implements this via its
// per-tenant DEK; callers in tests can pass a stub.
type SecretUnwrapper interface {
	UnwrapBlob(ctx context.Context, blob []byte) ([]byte, error)
}

// VerifyInbound is the high-level entry point: look up the
// integration's signing secret, verify the supplied (timestamp,
// signature, body) tuple, and log the outcome to
// integration_inbound_log. Returns a typed error so the handler
// can map to the right HTTP status (401 mismatch, 400 missing).
//
// Behaviour when no secret is configured:
//   - If `requireSecret` is true (production default), returns
//     ErrSecretNotConfigured — the caller MUST reject the request.
//   - If `requireSecret` is false (dev / migration window), returns
//     nil so existing callers continue to work while operators
//     populate secrets.
//
// The function ALWAYS writes an integration_inbound_log row so an
// operator can audit which IPs are hammering us with bad signatures.
func (s *Service) VerifyInbound(ctx context.Context, integrationID uuid.UUID, timestamp string, body []byte, signatureHex, sourceIP string, requireSecret bool, unwrap SecretUnwrapper) error {
	bodyHash := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(bodyHash[:])

	// Look up the stored signing secret. NULL → no enforcement
	// possible for this integration.
	var (
		enc    []byte
		ver    *int
		algo   string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT signing_secret_encrypted, signing_key_version,
		       COALESCE(signing_algorithm, 'hmac-sha256')
		  FROM integrations
		 WHERE id = $1`, integrationID).Scan(&enc, &ver, &algo)
	if err != nil {
		s.logInbound(ctx, integrationID, false, "lookup_failed", sourceIP, bodyHex)
		return fmt.Errorf("integrations: lookup signing secret: %w", err)
	}
	if len(enc) == 0 {
		if requireSecret {
			s.logInbound(ctx, integrationID, false, "no_secret", sourceIP, bodyHex)
			return ErrSecretNotConfigured
		}
		s.logInbound(ctx, integrationID, true, "no_secret_dev", sourceIP, bodyHex)
		return nil
	}
	if unwrap == nil {
		s.logInbound(ctx, integrationID, false, "no_unwrap", sourceIP, bodyHex)
		return errors.New("integrations: secret stored but no unwrapper provided")
	}
	secret, err := unwrap.UnwrapBlob(ctx, enc)
	if err != nil {
		s.logInbound(ctx, integrationID, false, "unwrap_failed", sourceIP, bodyHex)
		return fmt.Errorf("integrations: unwrap signing secret: %w", err)
	}

	// Algorithm dispatch. Today only hmac-sha256 is implemented;
	// extending to hmac-sha512 or ed25519 means adding a case +
	// rotating signing_algorithm via the operator API.
	switch algo {
	case "hmac-sha256", "":
		if err := Verify(string(secret), timestamp, body, signatureHex, VerifyOptions{}); err != nil {
			code := classifyVerifyError(err)
			s.logInbound(ctx, integrationID, false, code, sourceIP, bodyHex)
			// Surface bad-signature attempts as a per-integration
			// metric. A brute-force probe shows up as a flat-line
			// rate against a single integration_id+code label set;
			// alerting can page on sustained non-zero rate >1/min.
			observability.InboundHMACFailures.WithLabelValues(code).Inc()
			return err
		}
	default:
		s.logInbound(ctx, integrationID, false, "unsupported_algo", sourceIP, bodyHex)
		return fmt.Errorf("integrations: unsupported signing algorithm %q", algo)
	}

	s.logInbound(ctx, integrationID, true, "", sourceIP, bodyHex)
	return nil
}

// ErrSecretNotConfigured is returned when an integration has no
// signing secret set and the platform is configured to require one.
var ErrSecretNotConfigured = errors.New("integrations: no signing secret configured for this integration")

func classifyVerifyError(err error) string {
	switch {
	case errors.Is(err, ErrMissingSignature):
		return "missing_signature"
	case errors.Is(err, ErrTimestampSkew):
		return "skew"
	case errors.Is(err, ErrSignatureMismatch):
		return "mismatch"
	default:
		return "invalid_input"
	}
}

func (s *Service) logInbound(ctx context.Context, integrationID uuid.UUID, verified bool, rejection, sourceIP, bodySha string) {
	// Best-effort; never fail the verification path because the
	// audit insert failed (operator still gets the typed error).
	var ipArg any
	if sourceIP != "" {
		ipArg = sourceIP
	}
	var rejArg any
	if rejection != "" {
		rejArg = rejection
	}
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO integration_inbound_log
		    (integration_id, verified, rejection_code, source_ip, body_sha256)
		VALUES ($1,$2,$3,$4::inet,$5)`,
		integrationID, verified, rejArg, ipArg, bodySha)
}

// SetSigningSecret stores a new signing secret for an integration.
// Encrypts the plaintext under the vault DEK before writing. Pass
// empty plaintext to clear (disables inbound verification — caller
// must understand the implication).
func (s *Service) SetSigningSecret(ctx context.Context, integrationID uuid.UUID, plaintext string, wrapper interface {
	WrapBytes(ctx context.Context, blob []byte) ([]byte, int, error)
}) error {
	if plaintext == "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE integrations
			   SET signing_secret_encrypted = NULL,
			       signing_key_version = NULL,
			       updated_at = now()
			 WHERE id = $1`, integrationID)
		return err
	}
	if wrapper == nil {
		return errors.New("integrations: SetSigningSecret requires a non-nil wrapper")
	}
	enc, version, err := wrapper.WrapBytes(ctx, []byte(plaintext))
	if err != nil {
		return fmt.Errorf("integrations: wrap signing secret: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE integrations
		   SET signing_secret_encrypted = $2,
		       signing_key_version = $3,
		       signing_algorithm = COALESCE(signing_algorithm, 'hmac-sha256'),
		       updated_at = now()
		 WHERE id = $1`, integrationID, enc, version)
	return err
}
