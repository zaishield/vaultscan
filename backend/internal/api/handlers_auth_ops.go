package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

// ---- TOTP/MFA ------------------------------------------------------------

func mfaEnrollStart(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		if s.MFA == nil {
			internalErr(w, errMFANotWired)
			return
		}
		// Refuse re-enrollment for users who already have MFA. The
		// user_mfa INSERT uses ON CONFLICT DO UPDATE which would
		// clobber the existing TOTP secret with no second-factor
		// check — a session-stolen attacker (e.g. via XSS) could
		// silently replace the victim's MFA and lock them out.
		// Operators rotating their MFA must DELETE /api/v1/auth/mfa
		// first (that route is MFA-gated), then re-enroll.
		enrolled, err := s.MFA.IsEnrolled(r.Context(), id.UserID)
		if err != nil {
			internalErr(w, err)
			return
		}
		if enrolled {
			writeJSONError(w, http.StatusConflict, "already_enrolled",
				"MFA is already enrolled; disable it first (DELETE /api/v1/auth/mfa) then re-enroll")
			return
		}
		secret, err := s.MFA.StartEnrollment(r.Context(), id.UserID, id.Email, "VAULTSCAN")
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, secret)
	}
}

func mfaEnrollConfirm(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		var req struct {
			Code string `json:"code"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.MFA.ConfirmEnrollment(r.Context(), id.UserID, req.Code); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "enrolled"})
	}
}

// mfaVerify is the second-step call during login. The session token
// from the API's password-verify step carries mfa_required=true; once
// this endpoint succeeds, the caller exchanges it for a full token.
func mfaVerify(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID uuid.UUID `json:"user_id"`
			Code   string    `json:"code"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.MFA.Verify(r.Context(), req.UserID, req.Code); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "mfa_invalid", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "verified"})
	}
}

func mfaDisable(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		if err := s.MFA.Disable(r.Context(), id.UserID); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "disabled"})
	}
}

// ---- JWKS / JWT key management ------------------------------------------

func jwksHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Keys == nil {
			internalErr(w, errJWKSNotWired)
			return
		}
		set, err := s.Keys.PublicSet(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(set)
	}
}

func rotateJWTKey(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kid, err := s.Keys.Rotate(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "rotated", "new_kid": kid,
		})
	}
}

// ---- helpers --------------------------------------------------------------

var (
	errMFANotWired  = errPlain("MFA service not wired")
	errJWKSNotWired = errPlain("key manager not wired")
)

type errPlainT string

func (e errPlainT) Error() string { return string(e) }

func errPlain(s string) error { return errPlainT(s) }

// writeJSONError keeps the shape consistent with the rest of the API.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
