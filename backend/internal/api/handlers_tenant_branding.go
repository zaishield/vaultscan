// handlers_tenant_branding.go — tenant-level branding overrides +
// partner support-settings PUT.
//
// Routes:
//
//	GET    /api/v1/tenants/{tenant_id}/branding       — bundle for tenant
//	PUT    /api/v1/tenants/{tenant_id}/branding       — upsert override (manage_branding)
//	DELETE /api/v1/tenants/{tenant_id}/branding       — clear override (manage_branding)
//	PUT    /api/v1/partners/{partner_id}/support      — upsert support settings (manage_branding)
package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/partners"
)

// getTenantBranding returns the tenant's resolved branding bundle
// (partner branding with tenant overrides applied). Used by the
// portal when a tenant user logs in — the bundle drives chrome
// rendering so anyone in the tenant sees the customised look.
func getTenantBranding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		// Resolve the tenant's partner.
		t, err := s.Tenants.Get(r.Context(), tenantID)
		if err != nil {
			notFound(w)
			return
		}
		bundle, err := s.Branding.LoadBundleForTenant(r.Context(), t.PartnerID, tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	}
}

type tenantBrandingReq struct {
	ProductName    string `json:"product_name"`
	LogoURL        string `json:"logo_url"`
	FaviconURL     string `json:"favicon_url"`
	PrimaryColor   string `json:"primary_color"`
	SecondaryColor string `json:"secondary_color"`
	LegalFooter    string `json:"legal_footer"`
}

func putTenantBranding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		var req tenantBrandingReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		var actor *uuid.UUID
		if id, ierr := auth.FromContext(r.Context()); ierr == nil && id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Branding.SetTenantBranding(r.Context(), actor, tenantID, branding.TenantOverrideInput{
			ProductName:    req.ProductName,
			LogoURL:        req.LogoURL,
			FaviconURL:     req.FaviconURL,
			PrimaryColor:   req.PrimaryColor,
			SecondaryColor: req.SecondaryColor,
			LegalFooter:    req.LegalFooter,
		}); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func clearTenantBranding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		if err := s.Branding.ClearTenantBranding(r.Context(), tenantID); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	}
}

type supportSettingsReq struct {
	URL                string `json:"support_url"`
	Email              string `json:"support_email"`
	Phone              string `json:"support_phone"`
	SLAResponseMinutes int    `json:"sla_response_minutes"`
}

func putPartnerSupport(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		var req supportSettingsReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		var actor *uuid.UUID
		if id, ierr := auth.FromContext(r.Context()); ierr == nil && id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Branding.UpdateSupportSettings(r.Context(), actor, partnerID, branding.SupportSettingsInput{
			URL:                req.URL,
			Email:              req.Email,
			Phone:              req.Phone,
			SLAResponseMinutes: req.SLAResponseMinutes,
		}); err != nil {
			badRequest(w, err.Error())
			return
		}
		// Onboarding-checklist milestone — counts as "configured"
		// when at least one contact channel (url / email / phone)
		// is non-empty.
		if req.URL != "" || req.Email != "" || req.Phone != "" {
			_ = s.Partners.MarkMilestone(r.Context(), partnerID, partners.MilestoneSupport)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
