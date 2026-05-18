// handlers_inbound.go — inbound webhook callbacks.
//
// Layout:
//
//	POST /api/v1/integrations/{integration_id}/inbound
//	  Generic HMAC-SHA256 verified callback. Body is the raw bytes
//	  the partner POSTed; we verify the signature against the
//	  integration's stored secret and store the result in
//	  integration_inbound_log. Per-provider semantics (Slack
//	  acknowledgement, GitHub event dispatch, etc.) layer on top by
//	  reading the body after Verify succeeds.
//
//	POST /api/v1/integrations/{integration_id}/signing-secret
//	  Operator endpoint to rotate the inbound signing secret. Wraps
//	  plaintext under the evidence vault and writes the encrypted
//	  blob. Required permission: manage_integrations.
//
// Production posture: VAULTSCAN_REQUIRE_INBOUND_SIG=true (default)
// forces every callback to verify; integrations whose secret is
// unset are rejected with 403 secret_not_configured. Dev / migration
// windows can set it to false so existing wiring keeps working
// during the rollout.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
)

// inboundWebhook receives a partner-driven callback and verifies the
// HMAC-SHA256 signature. Body cap matches the platform max (32 MiB
// from middleware.MaxBodySize); for typical webhook bodies (<1 KiB)
// this is a non-event.
func inboundWebhook(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		integrationID, err := uuidParam(r, "integration_id")
		if err != nil {
			badRequest(w, "invalid integration_id")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			badRequest(w, "body too large or unreadable")
			return
		}

		// Header conventions:
		//   X-VaultScan-Timestamp    — RFC 3339 or unix seconds; the
		//   X-VaultScan-Signature    — hex HMAC-SHA256 (or "sha256=<hex>")
		// Providers that ship a Stripe-style combined header set
		// X-VaultScan-Signature alone to "t=...,v1=..." and we parse.
		ts := r.Header.Get("X-VaultScan-Timestamp")
		sig := r.Header.Get("X-VaultScan-Signature")
		if ts == "" && sig != "" {
			if t, sx := integrations.ParseStripe(sig); t != "" && sx != "" {
				ts, sig = t, sx
			}
		}

		require := os.Getenv("VAULTSCAN_REQUIRE_INBOUND_SIG") != "false"

		ip := ""
		if cIP := middleware.ClientIP(r); cIP != nil {
			ip = cIP.String()
		}
		verr := s.Integrations.VerifyInbound(r.Context(), integrationID,
			ts, body, sig, ip, require, s.Vault)
		if verr != nil {
			status := http.StatusUnauthorized
			code := "signature_invalid"
			switch {
			case errors.Is(verr, integrations.ErrMissingSignature):
				status, code = http.StatusBadRequest, "missing_signature"
			case errors.Is(verr, integrations.ErrTimestampSkew):
				status, code = http.StatusUnauthorized, "timestamp_skew"
			case errors.Is(verr, integrations.ErrSignatureMismatch):
				status, code = http.StatusUnauthorized, "signature_mismatch"
			case errors.Is(verr, integrations.ErrSecretNotConfigured):
				status, code = http.StatusForbidden, "secret_not_configured"
			}
			writeJSON(w, status, map[string]any{
				"error": map[string]string{"code": code, "message": verr.Error()},
			})
			return
		}

		// Verification passed. The default handler accepts the event
		// (audit row already written). Per-provider business logic
		// reads the body via a downstream subscriber.
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
	}
}

// putIntegrationSigningSecret rotates the per-integration signing
// secret. Operator-only; the new secret is wrapped under the evidence
// vault DEK before storage. Body shape: {"secret": "..."} — empty
// string clears (DISABLES verification, so the handler returns a
// confirmation envelope).
func putIntegrationSigningSecret(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		integrationID, err := uuidParam(r, "integration_id")
		if err != nil {
			badRequest(w, "invalid integration_id")
			return
		}
		var req struct {
			Secret string `json:"secret"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&req); err != nil {
			badRequest(w, "invalid JSON body")
			return
		}
		if err := s.Integrations.SetSigningSecret(r.Context(), integrationID, req.Secret, s.Vault); err != nil {
			internalErr(w, err)
			return
		}
		resp := map[string]any{"status": "ok"}
		if req.Secret == "" {
			resp["warning"] = "signing secret cleared; inbound verification disabled for this integration"
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
