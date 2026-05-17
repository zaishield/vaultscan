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
