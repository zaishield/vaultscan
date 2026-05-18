// handlers_billing.go — partner billing-quota REST surface.
//
// Routes (all under /api/v1/partners/{partner_id}/billing, gated by
// the manage_branding permission as the partner-admin role floor):
//
//	GET    /plan         — current active plan + live usage
//	PUT    /plan         — operator assigns/changes plan
//	GET    /usage        — live usage counters (no plan context)
//	GET    /blocks       — recent quota-block audit rows
//
// Quota refusal at the integration points returns 429 with a JSON
// body shaped { error: { code: "quota_exceeded", kind, current,
// limit, plan } } so the portal can render an "Upgrade your plan"
// prompt without parsing the message string.
package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/billing"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
	"github.com/zaishield/vaultscan/backend/internal/tenants"
)

// quotaErrorJSON maps a billing.ErrQuotaExceeded to a 429 envelope
// with all the fields a UI needs. Returns true if it handled the
// error so the caller can early-return.
func quotaErrorJSON(w http.ResponseWriter, err error) bool {
	var qe *billing.ErrQuotaExceeded
	if !errors.As(err, &qe) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error": map[string]any{
			"code":    "quota_exceeded",
			"kind":    string(qe.Kind),
			"current": qe.Current,
			"limit":   qe.Limit,
			"plan":    qe.Plan,
			"message": qe.Error(),
		},
	})
	return true
}

// residencyErrorJSON maps tenants.ErrResidencyViolation to a 451
// Unavailable For Legal Reasons. The 451 status is the closest fit
// for "we can't serve this here because of a residency commitment" —
// the response carries the body shape the portal renders ("your
// data is pinned to region X; route your request via api-X.").
func residencyErrorJSON(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, tenants.ErrResidencyViolation) {
		return false
	}
	writeJSON(w, http.StatusUnavailableForLegalReasons, map[string]any{
		"error": map[string]any{
			"code":    "data_residency_violation",
			"message": err.Error(),
		},
	})
	return true
}

func getBillingPlan(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		plan, err := s.Billing.CurrentPlan(r.Context(), partnerID)
		if err != nil {
			internalErr(w, err)
			return
		}
		usage, err := s.Billing.UsageFor(r.Context(), partnerID, plan)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"plan":  plan, // nil = "no plan = unlimited" — portal renders accordingly
			"usage": usage,
		})
	}
}

type assignPlanReq struct {
	PlanCode      string `json:"plan_code"`
	Name          string `json:"name"`
	AssetQuota    int    `json:"asset_quota"`
	ScanQuota     int    `json:"scan_quota"`
	AgentQuota    int    `json:"agent_quota"`
	OveragePolicy string `json:"overage_policy"`
	Currency      string `json:"currency"`
	PriceCents    int64  `json:"price_cents"`
	BillingCycle  string `json:"billing_cycle"`
}

func putBillingPlan(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		var req assignPlanReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if req.PlanCode == "" {
			badRequest(w, "plan_code required")
			return
		}
		var actor *uuid.UUID
		if id, ierr := auth.FromContext(r.Context()); ierr == nil && id != nil {
			a := id.UserID
			actor = &a
		}
		plan, err := s.Billing.AssignPlan(r.Context(), billing.AssignInput{
			PartnerID:     partnerID,
			PlanCode:      req.PlanCode,
			Name:          req.Name,
			AssetQuota:    req.AssetQuota,
			ScanQuota:     req.ScanQuota,
			AgentQuota:    req.AgentQuota,
			OveragePolicy: req.OveragePolicy,
			Currency:      req.Currency,
			PriceCents:    req.PriceCents,
			BillingCycle:  req.BillingCycle,
		}, actor)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, plan)
	}
}

func getBillingUsage(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		plan, _ := s.Billing.CurrentPlan(r.Context(), partnerID)
		usage, err := s.Billing.UsageFor(r.Context(), partnerID, plan)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, usage)
	}
}

func listBillingBlocks(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		limit, _, ok := parsePagination(w, r, 50, 500)
		if !ok {
			return
		}
		out, err := s.Billing.RecentBlocks(r.Context(), partnerID, limit)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

// actorIDOrNil is a small helper used by handlers that need the
// authenticated user's id as *uuid.UUID, returning nil when there's
// no identity. The Billing handlers use it once; broadening to
// other handlers is fine.
func actorIDOrNil(id *auth.Identity) *uuid.UUID {
	if id == nil {
		return nil
	}
	a := id.UserID
	return &a
}

// getMyUsage is the self-service customer-facing usage endpoint at
// GET /api/v1/usage. It returns the calling identity's plan + live
// usage + the configured API rate-limit caps so a client can answer
// "how much room do I have left?" without operator help.
//
// Resolution order for the partner whose plan we read:
//
//  1. identity.PartnerID — partner-staff tokens carry this directly
//  2. partner_customer_mapping[tenant_id=identity.TenantID] — tenant
//     users see the plan of the partner that owns them
//  3. fall back to the platform-direct DefaultPartnerID when neither
//     is set (rare; mostly platform-admin sessions)
//
// Rate-limit caps reflect what the API enforces *today*; the limiter
// backend doesn't expose remaining-count cheaply (Redis sliding
// window would need a peek script), so we report the static cap +
// window and let the client subtract their observed 429s.
func getMyUsage(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		partnerID := resolveCallerPartner(r, s, id)

		var plan *billing.Plan
		var usage *billing.Usage
		if partnerID != uuid.Nil {
			plan, _ = s.Billing.CurrentPlan(r.Context(), partnerID)
			usage, _ = s.Billing.UsageFor(r.Context(), partnerID, plan)
		}

		windowSec := s.Cfg.RateLimitWindowSec
		if windowSec <= 0 {
			windowSec = 60
		}
		limit := s.Cfg.RateLimitRPS * windowSec

		rl := map[string]any{
			"per_identity_rps":      s.Cfg.RateLimitRPS,
			"window_seconds":        windowSec,
			"per_tenant_multiplier": s.Cfg.PerTenantRateLimitMultiplier,
			"limit_per_window":      limit,
		}
		// Best-effort Peek for "remaining tokens". -1 sentinel = not
		// available (Redis unreachable, or backend doesn't implement
		// Peek); UIs MUST display this as "unknown" rather than
		// guessing zero.
		if peekable, ok := s.Limiter.(middleware.Peekable); ok && peekable != nil {
			identityRemain, _ := peekable.Peek(r.Context(), middleware.IdentityKey(r), limit, windowSec)
			rl["identity_remaining"] = identityRemain
			if id.TenantID != nil {
				tenantLim := limit * s.Cfg.PerTenantRateLimitMultiplier
				if tenantLim > 0 {
					tenantRemain, _ := peekable.Peek(r.Context(),
						"tenant:"+id.TenantID.String(), tenantLim, windowSec)
					rl["tenant_remaining"] = tenantRemain
					rl["tenant_limit_per_window"] = tenantLim
				}
			}
		} else {
			rl["identity_remaining"] = -1
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"identity": map[string]any{
				"user_id":    id.UserID,
				"tenant_id":  id.TenantID,
				"partner_id": partnerID,
			},
			"plan":       plan,
			"usage":      usage,
			"rate_limit": rl,
		})
	}
}

// resolveCallerPartner picks the partner whose billing plan applies
// to this caller. Order matches getMyUsage docs.
func resolveCallerPartner(r *http.Request, s *Services, id *auth.Identity) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	if id.PartnerID != nil && *id.PartnerID != uuid.Nil {
		return *id.PartnerID
	}
	if id.TenantID != nil {
		var p uuid.UUID
		err := s.Pool.QueryRow(r.Context(),
			`SELECT partner_id FROM partner_customer_mapping WHERE tenant_id=$1 LIMIT 1`,
			*id.TenantID).Scan(&p)
		if err == nil {
			return p
		}
	}
	return s.DefaultPartnerID
}
