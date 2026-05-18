// middleware_impersonation.go — runtime enforcement for support-
// engineer impersonation JWTs.
//
// When a request's JWT carries an `impersonation_session_id` claim,
// this middleware:
//
//   1. Looks up the session in support_impersonation_sessions.
//   2. Refuses the request if the session is ended or past
//      expires_at (the operator hit the cap, or End was called).
//   3. Increments the session's request_count via impersonation.
//      Service.Touch — so the audit team can later see "how many
//      requests did this engineer make under this session" without
//      scanning the audit log.
//
// Sits AFTER middleware.Auth (which decodes the JWT) and BEFORE
// the routes that actually do work.

package middleware

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/impersonation"
)

// ImpersonationEnforce wires the impersonation service so the
// session counter increments + expired sessions are refused at the
// edge.
//
// For non-impersonation JWTs this is a pass-through (no DB hit).
func ImpersonationEnforce(svc *impersonation.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := auth.FromContext(r.Context())
			if id == nil || id.ImpersonationSessionID == "" {
				// Non-impersonation JWT — fast-path through.
				next.ServeHTTP(w, r)
				return
			}
			sid, err := uuid.Parse(id.ImpersonationSessionID)
			if err != nil {
				http.Error(w, `{"error":"invalid_impersonation_session"}`, http.StatusUnauthorized)
				return
			}
			if err := svc.Touch(r.Context(), sid); err != nil {
				// Session ended or expired — reject. The operator
				// must Start a new session.
				http.Error(w, `{"error":"impersonation_session_expired"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
