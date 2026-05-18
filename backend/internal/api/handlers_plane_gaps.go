// handlers_plane_gaps.go — HTTP layer for the external + internal
// plane endpoints added in migration 0061:
//
//   External (customer-facing):
//     GET    /api/v1/tenants/{tenant_id}/sso
//     PUT    /api/v1/tenants/{tenant_id}/sso
//     POST   /api/v1/tenants/{tenant_id}/scim/tokens
//     GET    /api/v1/tenants/{tenant_id}/scim/tokens
//     DELETE /api/v1/tenants/{tenant_id}/scim/tokens/{token_id}
//     POST   /api/v1/partners/{partner_id}/billing/plan-requests
//     GET    /api/v1/partners/{partner_id}/billing/plan-requests
//     POST   /api/v1/compliance/tenants/{tenant_id}/snapshot
//     GET    /api/v1/compliance/tenants/{tenant_id}/rollup
//
//   Internal (operator-facing):
//     GET    /api/v1/platform/billing/plan-requests
//     POST   /api/v1/platform/billing/plan-requests/{id}/decide
//     POST   /api/v1/platform/billing/usage-adjustments
//     POST   /api/v1/platform/impersonate
//     DELETE /api/v1/platform/impersonate/{session_id}
//     GET    /api/v1/platform/impersonate/active
//     POST   /api/v1/platform/tenants/{tenant_id}/quarantine
//     DELETE /api/v1/platform/tenants/{tenant_id}/quarantine
//     POST   /api/v1/platform/tenants/{tenant_id}/migrate

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/impersonation"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
	"github.com/zaishield/vaultscan/backend/internal/scimtokens"
	"github.com/zaishield/vaultscan/backend/internal/ssoconfig"
)

// ----------------- SSO config ---------------------------------------

func getSSOConfig(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		c, err := s.SSOConfig.Get(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

func putSSOConfig(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		var in ssoconfig.SetInput
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			actor = &id.UserID
		}
		c, err := s.SSOConfig.Set(r.Context(), tenantID, in, actor)
		if err != nil {
			if errors.Is(err, ssoconfig.ErrInvalidProvider) {
				badRequest(w, err.Error())
				return
			}
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

// ----------------- SCIM tokens --------------------------------------

func createSCIMToken(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		var in struct {
			Label  string `json:"label"`
			TTLSec int    `json:"ttl_seconds,omitempty"` // 0 = no expiry
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		res, err := s.SCIMTokens.Create(r.Context(), tenantID, in.Label,
			time.Duration(in.TTLSec)*time.Second, id.UserID)
		if err != nil {
			if errors.Is(err, scimtokens.ErrTokenLabelDuplicate) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, res)
	}
}

func listSCIMTokens(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		toks, err := s.SCIMTokens.List(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, toks)
	}
}

func revokeSCIMToken(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		tokenID, err := uuidParam(r, "token_id")
		if err != nil {
			badRequest(w, "invalid token_id")
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := s.SCIMTokens.Revoke(r.Context(), tenantID, tokenID, id.UserID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ----------------- Plan-change requests -----------------------------

func filePlanRequest(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		var in struct {
			CurrentPlan   string `json:"current_plan"`
			RequestedPlan string `json:"requested_plan"`
			Note          string `json:"note,omitempty"`
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		req, err := s.PlanRequests.File(r.Context(), partnerID, id.UserID,
			in.CurrentPlan, in.RequestedPlan, in.Note)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, req)
	}
}

func listPartnerPlanRequests(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		reqs, err := s.PlanRequests.ListForPartner(r.Context(), partnerID, 50)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, reqs)
	}
}

func listPendingPlanRequests(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqs, err := s.PlanRequests.ListPending(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, reqs)
	}
}

func decidePlanRequest(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID, err := uuidParam(r, "id")
		if err != nil {
			badRequest(w, "invalid id")
			return
		}
		var in struct {
			Status string `json:"status"` // approved | rejected | cancelled
			Note   string `json:"decision_note,omitempty"`
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		req, err := s.PlanRequests.Decide(r.Context(), reqID, id.UserID, in.Status, in.Note)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, req)
	}
}

// ----------------- Compliance rollup --------------------------------

func getComplianceRollup(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		includeBreakdown := r.URL.Query().Get("include") == "breakdown"
		rollups, err := s.ComplianceEval.RollupAll(r.Context(), tenantID, includeBreakdown)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rollups)
	}
}

func snapshotCompliance(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		rollups, err := s.ComplianceEval.Snapshot(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rollups)
	}
}

// ----------------- Support impersonation ----------------------------

func startImpersonation(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			TargetUserID uuid.UUID `json:"target_user_id"`
			TicketRef    string    `json:"ticket_ref"`
			Reason       string    `json:"reason"`
			DurationSec  int       `json:"duration_seconds,omitempty"`
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sess, err := s.Impersonation.Start(r.Context(), id.UserID, impersonation.StartInput{
			TargetUserID: in.TargetUserID,
			TicketRef:    in.TicketRef,
			Reason:       in.Reason,
			Duration:     time.Duration(in.DurationSec) * time.Second,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		// Mint a short-lived JWT for the impersonated identity.
		// The TenantID + Roles claims reflect the TARGET (so RLS +
		// permission checks evaluate as the customer would see),
		// but the `impersonation_session_id` claim ties every
		// request back to the operator + the open session.
		ttl := time.Until(sess.ExpiresAt)
		tok, err := s.Verifier.IssueImpersonationToken(&impAdapter{sess: sess, s: s}, ttl)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"session": sess,
			"token":   tok,
			"expires_at": sess.ExpiresAt,
		})
	}
}

func endImpersonation(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := uuidParam(r, "session_id")
		if err != nil {
			badRequest(w, "invalid session_id")
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := s.Impersonation.End(r.Context(), sessionID, id.UserID); err != nil {
			internalErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func listActiveImpersonations(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := s.Impersonation.Active(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, sessions)
	}
}

// ----------------- Tenant lifecycle (platform admin) ----------------

func quarantineTenant(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			actor = &id.UserID
		}
		if err := s.Tenants.QuarantineForDeletion(r.Context(), tenantID, actor, in.Reason); err != nil {
			badRequest(w, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func cancelQuarantine(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			actor = &id.UserID
		}
		if err := s.Tenants.CancelQuarantine(r.Context(), tenantID, actor); err != nil {
			badRequest(w, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func migrateTenantPartner(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		var in struct {
			ToPartnerID uuid.UUID `json:"to_partner_id"`
			Reason      string    `json:"reason"`
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := s.Tenants.MigrateToPartner(r.Context(), tenantID,
			in.ToPartnerID, id.UserID, in.Reason); err != nil {
			badRequest(w, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ----------------- Usage adjustment (finance) -----------------------

func createUsageAdjustment(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			PartnerID uuid.UUID `json:"partner_id"`
			Month     string    `json:"month"`        // YYYY-MM
			Metric    string    `json:"metric"`       // scans_run | users_active | …
			Delta     int       `json:"delta"`        // positive = credit
			Reason    string    `json:"reason"`
			TicketRef string    `json:"ticket_ref,omitempty"`
		}
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		if in.Metric == "" || in.Reason == "" {
			badRequest(w, "metric + reason required")
			return
		}
		month, err := time.Parse("2006-01", in.Month)
		if err != nil {
			badRequest(w, "month must be YYYY-MM")
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := s.Pool.Exec(r.Context(), `
			INSERT INTO billing_usage_adjustments(partner_id, month, metric,
			    delta, reason, ticket_ref, created_by)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), $7)`,
			in.PartnerID, month, in.Metric, in.Delta, in.Reason, in.TicketRef, id.UserID); err != nil {
			internalErr(w, err)
			return
		}
		// Audit + bus emit. Both are best-effort (don't fail the
		// HTTP response if either trips); the row already landed.
		if s.Audit != nil {
			_ = s.Audit.Record(r.Context(), audit.Entry{
				Event:      "billing.usage_adjusted",
				ActorID:    &id.UserID,
				TargetType: "partner",
				TargetID:   in.PartnerID.String(),
				Payload: map[string]any{
					"month": in.Month, "metric": in.Metric, "delta": in.Delta,
					"reason": in.Reason, "ticket_ref": in.TicketRef,
				},
			})
		}
		if s.Bus != nil {
			s.Bus.Publish(r.Context(), eventbus.Event{
				Type:      eventbus.BillingUsageAdjusted,
				PartnerID: &in.PartnerID,
				ActorID:   &id.UserID,
				Payload: map[string]any{
					"month": in.Month, "metric": in.Metric, "delta": in.Delta,
				},
			})
		}
		w.WriteHeader(http.StatusCreated)
	}
}

// impAdapter implements auth.impersonationSessionLike using an
// impersonation.Session + Services to look up missing identity
// fields (target roles, platform/partner IDs). Keeps the auth
// package free of an import cycle on the impersonation package.
type impAdapter struct {
	sess *impersonation.Session
	s    *Services
}

func (a *impAdapter) IDStr() string           { return a.sess.ID.String() }
func (a *impAdapter) OperatorIDStr() string   { return a.sess.OperatorID.String() }
func (a *impAdapter) TargetUserIDStr() string { return a.sess.TargetUserID.String() }
func (a *impAdapter) TargetEmailStr() string  { return a.sess.TargetEmail }
func (a *impAdapter) TargetTenantStr() string {
	if a.sess.TargetTenant == nil {
		return ""
	}
	return a.sess.TargetTenant.String()
}
func (a *impAdapter) TargetRolesList() []string {
	// Resolve the target user's roles via the users service so the
	// JWT permission set mirrors what the target would normally see.
	if a.s == nil || a.s.Users == nil {
		return nil
	}
	roles, _ := a.s.Users.RolesForUser(context.Background(), a.sess.TargetUserID)
	return roles
}
func (a *impAdapter) PlatformIDStr() string {
	// Pull the user's platform_id directly.
	var pid string
	_ = a.s.Pool.QueryRow(context.Background(),
		`SELECT platform_id::text FROM users WHERE id = $1`,
		a.sess.TargetUserID).Scan(&pid)
	return pid
}
func (a *impAdapter) PartnerIDStr() string {
	if a.sess.TargetTenant == nil {
		return ""
	}
	// Look up the tenant's partner_id.
	var pid string
	_ = a.s.Pool.QueryRow(context.Background(),
		`SELECT partner_id::text FROM tenants WHERE id = $1`,
		a.sess.TargetTenant).Scan(&pid)
	return pid
}

// _ = middleware.RequirePermission silences the import when this
// file is included in builds that don't reference middleware
// directly elsewhere — the route mount in server.go uses it.
var _ = middleware.RequirePermission
