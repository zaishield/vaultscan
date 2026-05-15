// HTTP handlers binding services to routes. Each handler is intentionally
// small: parse → invoke service → write JSON.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/authdocs"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/models"
	"github.com/zaishield/vaultscan/backend/internal/partners"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
	"github.com/zaishield/vaultscan/backend/internal/tenants"
)

// ----- helpers ------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error": map[string]string{"code": "bad_request", "message": msg}})
}

func internalErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]any{
		"error": map[string]string{"code": "internal", "message": err.Error()}})
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error": map[string]string{"code": "not_found", "message": "resource not found"}})
}

func decode(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("missing body")
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func uuidParam(r *http.Request, name string) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, name))
}

func clientIP(r *http.Request) net.IP {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			v = v[:i]
		}
		return net.ParseIP(strings.TrimSpace(v))
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

// ----- Branding ----------------------------------------------------------

func brandingByDomain(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			domain = strings.Split(r.Host, ":")[0]
		}
		bundle, err := s.Branding.ResolveByDomain(r.Context(), domain)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	}
}

// ----- dev token ---------------------------------------------------------

type devTokenReq struct {
	UserID     string   `json:"user_id"`
	PlatformID string   `json:"platform_id"`
	PartnerID  string   `json:"partner_id"`
	TenantID   string   `json:"tenant_id"`
	Email      string   `json:"email"`
	FullName   string   `json:"full_name"`
	Roles      []string `json:"roles"`
	MFA        bool     `json:"mfa"`
	TTLSeconds int      `json:"ttl_seconds"`
}

func devToken(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Cfg.Env != "development" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "dev tokens disabled"})
			return
		}
		var req devTokenReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if req.UserID == "" {
			req.UserID = uuid.New().String()
		}
		if req.PlatformID == "" {
			req.PlatformID = "00000000-0000-0000-0000-0000000000a1"
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl == 0 {
			ttl = 12 * time.Hour
		}
		token, err := s.Verifier.IssueDevToken(auth.VaultscanClaims{
			Email: req.Email, FullName: req.FullName,
			PlatformID: req.PlatformID, PartnerID: req.PartnerID, TenantID: req.TenantID,
			Roles: req.Roles, MFA: req.MFA,
			RegisteredClaims: jwtClaimsRegistered(req.UserID, ttl),
		})
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}

// ----- Tenants -----------------------------------------------------------

type createTenantReq struct {
	PartnerID     string `json:"partner_id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	IsolationMode string `json:"isolation_mode"`
}

func createTenant(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createTenantReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		partnerID, err := uuid.Parse(req.PartnerID)
		if err != nil {
			badRequest(w, "partner_id required")
			return
		}
		t, err := s.Tenants.Create(r.Context(), &id.UserID, tenants.CreateInput{
			PlatformID: id.PlatformID, PartnerID: partnerID,
			Name: req.Name, Slug: req.Slug, IsolationMode: req.IsolationMode,
		})
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	}
}

func getTenant(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		t, err := s.Tenants.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

func listTenants(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := auth.FromContext(r.Context())
		var partnerID *uuid.UUID
		if v := r.URL.Query().Get("partner_id"); v != "" {
			pid, err := uuid.Parse(v)
			if err == nil {
				partnerID = &pid
			}
		} else if id.PartnerID != nil && !id.HasRole("zaishield_super_admin") {
			partnerID = id.PartnerID
		}
		out, err := s.Tenants.List(r.Context(), tenants.ListFilter{
			PlatformID: id.PlatformID, PartnerID: partnerID,
		})
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

// ----- Partners ----------------------------------------------------------

type createPartnerReq struct {
	ParentID string `json:"parent_id"`
	TypeCode string `json:"type"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
}

func createPartner(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createPartnerReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var parent *uuid.UUID
		if req.ParentID != "" {
			pp, err := uuid.Parse(req.ParentID)
			if err != nil {
				badRequest(w, "bad parent_id")
				return
			}
			parent = &pp
		}
		p, err := s.Partners.Create(r.Context(), &id.UserID, partners.CreateInput{
			PlatformID: id.PlatformID, ParentID: parent,
			TypeCode: req.TypeCode, Name: req.Name, Slug: req.Slug,
		})
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, p)
	}
}

func getPartner(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		p, err := s.Partners.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, p)
	}
}

func listPartners(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := auth.FromContext(r.Context())
		out, err := s.Partners.List(r.Context(), id.PlatformID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func updateBranding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pid, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var in branding.UpdateBrandingInput
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		if err := s.Branding.UpdateBranding(r.Context(), &identity.UserID, pid, in); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func hierarchyForTenant(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		out, err := s.Partners.HierarchyForTenant(r.Context(), tid)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func addPartnerDomain(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pid, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			Domain  string `json:"domain"`
			Primary bool   `json:"is_primary"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.Branding.AddDomain(r.Context(), pid, req.Domain, req.Primary); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
	}
}

// ----- Engagements / Scope / AuthDocs ------------------------------------

type createEngagementReq struct {
	PartnerID  string `json:"partner_id"`
	TenantID   string `json:"tenant_id"`
	ClientID   string `json:"client_id"`
	Code       string `json:"code"`
	Name       string `json:"name"`
	Description string `json:"description"`
	StartsAt   time.Time `json:"starts_at"`
	EndsAt     time.Time `json:"ends_at"`
	Intensity  string    `json:"intensity"`
	EmergencyName string `json:"emergency_contact_name"`
	EmergencyMail string `json:"emergency_contact_email"`
	EmergencyPhone string `json:"emergency_contact_phone"`
}

func createEngagement(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createEngagementReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		partnerID, err1 := uuid.Parse(req.PartnerID)
		tenantID, err2 := uuid.Parse(req.TenantID)
		if err1 != nil || err2 != nil {
			badRequest(w, "partner_id and tenant_id required")
			return
		}
		var clientID *uuid.UUID
		if req.ClientID != "" {
			cid, err := uuid.Parse(req.ClientID)
			if err == nil {
				clientID = &cid
			}
		}
		e, err := s.Engagements.Create(r.Context(), &id.UserID, engagements.CreateInput{
			PlatformID: id.PlatformID, PartnerID: partnerID, TenantID: tenantID,
			ClientID: clientID, Code: req.Code, Name: req.Name, Description: req.Description,
			StartsAt: req.StartsAt, EndsAt: req.EndsAt, Intensity: req.Intensity,
			EmergencyName: req.EmergencyName, EmergencyMail: req.EmergencyMail, EmergencyPhone: req.EmergencyPhone,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, e)
	}
}

func getEngagement(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "engagement_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		e, err := s.Engagements.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func listEngagements(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		out, err := s.Engagements.ListByTenant(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func activateEngagement(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "engagement_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		if err := s.Engagements.Activate(r.Context(), &identity.UserID, id); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
	}
}

type addScopeReq struct {
	EngagementID string `json:"engagement_id"`
	TargetType   string `json:"target_type"`
	TargetValue  string `json:"target_value"`
	Plane        string `json:"plane"`
	Notes        string `json:"notes"`
}

func addScope(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req addScopeReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		eid, err := uuid.Parse(req.EngagementID)
		if err != nil {
			badRequest(w, "engagement_id required")
			return
		}
		identity, _ := auth.FromContext(r.Context())
		t, err := s.Engagements.AddScope(r.Context(), &identity.UserID, eid, req.TargetType, req.TargetValue, req.Plane, req.Notes)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	}
}

func listScope(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		eid, err := uuidParam(r, "engagement_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		out, err := s.Engagements.ListScope(r.Context(), eid)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func approveScope(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, err := uuidParam(r, "scope_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		if err := s.Engagements.ApproveScope(r.Context(), &identity.UserID, sid); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
	}
}

func uploadAuthDoc(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		eid, err := uuidParam(r, "engagement_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		title := r.URL.Query().Get("title")
		dtype := r.URL.Query().Get("type")
		if title == "" {
			title = "Authorization Letter"
		}
		if dtype == "" {
			dtype = "letter"
		}
		identity, _ := auth.FromContext(r.Context())
		id, err := s.AuthDocs.Upload(r.Context(), &identity.UserID, authdocs.UploadInput{
			EngagementID: eid, Title: title, DocumentType: dtype,
			Body: r.Body, ContentType: r.Header.Get("Content-Type"),
		})
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
	}
}

// ----- Assets ------------------------------------------------------------

type createAssetReq struct {
	PartnerID    string         `json:"partner_id"`
	TenantID     string         `json:"tenant_id"`
	EngagementID string         `json:"engagement_id"`
	AssetType    string         `json:"asset_type"`
	Name         string         `json:"name"`
	Value        string         `json:"value"`
	Plane        string         `json:"plane"`
	Criticality  string         `json:"criticality"`
	Owner        string         `json:"owner"`
	Environment  string         `json:"environment"`
	CloudProvider string        `json:"cloud_provider"`
	Tags         []string       `json:"tags"`
	Metadata     map[string]any `json:"metadata"`
}

func createAsset(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createAssetReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		partnerID, _ := uuid.Parse(req.PartnerID)
		tenantID, _ := uuid.Parse(req.TenantID)
		var eng *uuid.UUID
		if req.EngagementID != "" {
			eid, err := uuid.Parse(req.EngagementID)
			if err == nil {
				eng = &eid
			}
		}
		a, err := s.Assets.Create(r.Context(), assets.CreateInput{
			PlatformID: id.PlatformID, PartnerID: partnerID, TenantID: tenantID,
			EngagementID: eng, AssetType: req.AssetType, Name: req.Name, Value: req.Value,
			Plane: req.Plane, Criticality: req.Criticality, Owner: req.Owner,
			Environment: req.Environment, CloudProvider: req.CloudProvider,
			Tags: req.Tags, Metadata: req.Metadata, CreatedBy: &id.UserID,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, a)
	}
}

func listAssets(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		f := assets.ListFilter{TenantID: tenantID}
		if v := r.URL.Query().Get("engagement_id"); v != "" {
			eid, err := uuid.Parse(v)
			if err == nil {
				f.EngagementID = &eid
			}
		}
		f.AssetType = r.URL.Query().Get("asset_type")
		f.Plane = r.URL.Query().Get("plane")
		f.Criticality = r.URL.Query().Get("criticality")
		f.Search = r.URL.Query().Get("q")
		f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
		f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
		out, err := s.Assets.List(r.Context(), f)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func importAssetsCSV(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, _ := auth.FromContext(r.Context())
		partnerID, _ := uuid.Parse(r.URL.Query().Get("partner_id"))
		tenantID, _ := uuid.Parse(r.URL.Query().Get("tenant_id"))
		var eng *uuid.UUID
		if v := r.URL.Query().Get("engagement_id"); v != "" {
			eid, err := uuid.Parse(v)
			if err == nil {
				eng = &eid
			}
		}
		created, _, err := s.Assets.ImportCSV(r.Context(), assets.CreateInput{
			PlatformID: identity.PlatformID, PartnerID: partnerID, TenantID: tenantID,
			EngagementID: eng, CreatedBy: &identity.UserID,
		}, r.Body)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"created": created})
	}
}

// ----- Scans -------------------------------------------------------------

func listScanProfiles(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := s.ScanOrch.Profiles(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

type submitScanReq struct {
	PartnerID    string    `json:"partner_id"`
	TenantID     string    `json:"tenant_id"`
	EngagementID string    `json:"engagement_id"`
	ProfileCode  string    `json:"profile_code"`
	Region       string    `json:"region"`
	AgentID      string    `json:"agent_id"`
	Targets      []string  `json:"targets"`
	ScheduleAt   time.Time `json:"schedule_at"`
	Intensity    string    `json:"intensity"`
}

func submitExternalScan(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		submitScan(s, "external", w, r)
	}
}
func submitInternalScan(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		submitScan(s, "internal", w, r)
	}
}

func submitScan(s *Services, plane string, w http.ResponseWriter, r *http.Request) {
	var req submitScanReq
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	id, _ := auth.FromContext(r.Context())
	partnerID, _ := uuid.Parse(req.PartnerID)
	tenantID, _ := uuid.Parse(req.TenantID)
	engagementID, err := uuid.Parse(req.EngagementID)
	if err != nil {
		badRequest(w, "engagement_id required")
		return
	}
	var agentID *uuid.UUID
	if req.AgentID != "" {
		aid, err := uuid.Parse(req.AgentID)
		if err == nil {
			agentID = &aid
		}
	}
	var schedule *time.Time
	if !req.ScheduleAt.IsZero() {
		schedule = &req.ScheduleAt
	}
	job, decision, err := s.ScanOrch.Submit(r.Context(), scanorch.SubmitInput{
		PlatformID: id.PlatformID, PartnerID: partnerID, TenantID: tenantID,
		EngagementID: engagementID, ProfileCode: req.ProfileCode, Plane: plane,
		Region: req.Region, AgentID: agentID, Targets: req.Targets,
		ScheduleAt: schedule, RequestedBy: &id.UserID, Intensity: req.Intensity,
	})
	if err != nil {
		internalErr(w, err)
		return
	}
	if decision != nil && decision.Code != scopeguard.DecisionApproved &&
		decision.Code != scopeguard.DecisionRequiresManualApproval {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": map[string]any{
				"code": "scope_guard_blocked", "decision": decision,
			},
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"job": job, "scope_guard": decision})
}

func getScan(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "scan_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		j, err := s.ScanOrch.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, j)
	}
}

func listScans(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		out, err := s.ScanOrch.ListByTenant(r.Context(), tenantID, limit)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func approveScan(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "scan_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		j, err := s.ScanOrch.Approve(r.Context(), id, &identity.UserID)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, j)
	}
}

func emergencyStop(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JobID    string `json:"job_id"`
			TenantID string `json:"tenant_id"`
			AgentID  string `json:"agent_id"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		var scope scanorch.EmergencyScope
		if req.JobID != "" {
			id, _ := uuid.Parse(req.JobID)
			scope.JobID = &id
		}
		if req.TenantID != "" {
			id, _ := uuid.Parse(req.TenantID)
			scope.TenantID = &id
		}
		if req.AgentID != "" {
			id, _ := uuid.Parse(req.AgentID)
			scope.AgentID = &id
		}
		count, err := s.ScanOrch.EmergencyStop(r.Context(), &identity.UserID, scope)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"halted_jobs": count})
	}
}

// ----- Agents ------------------------------------------------------------

type provisionAgentReq struct {
	PartnerID  string `json:"partner_id"`
	TenantID   string `json:"tenant_id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	FormFactor string `json:"form_factor"`
}

func provisionAgent(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req provisionAgentReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		partnerID, _ := uuid.Parse(req.PartnerID)
		tenantID, _ := uuid.Parse(req.TenantID)
		a, token, err := s.Agents.Provision(r.Context(), agents.CreateInput{
			PlatformID: identity.PlatformID, PartnerID: partnerID, TenantID: tenantID,
			Name: req.Name, Location: req.Location, FormFactor: req.FormFactor, CreatedBy: &identity.UserID,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"agent": a, "enrollment_token": token,
			"note": "Token shown once. Use POST /api/v1/agents/enroll on the gateway to bind a certificate.",
		})
	}
}

func listAgents(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		out, err := s.Agents.ListByTenant(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func getAgent(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		a, err := s.Agents.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, a)
	}
}

func getAgentPolicy(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		p, err := s.Agents.Policy(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, p)
	}
}

func updateAgentPolicy(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var p models.AgentPolicy
		if err := decode(r, &p); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.Agents.UpdatePolicy(r.Context(), id, p); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ----- Findings ----------------------------------------------------------

func listFindings(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		f := findings.ListFilter{TenantID: tenantID}
		if v := r.URL.Query().Get("engagement_id"); v != "" {
			eid, err := uuid.Parse(v)
			if err == nil {
				f.EngagementID = &eid
			}
		}
		if v := r.URL.Query().Get("severity"); v != "" {
			f.Severity = strings.Split(v, ",")
		}
		if v := r.URL.Query().Get("status"); v != "" {
			f.Status = strings.Split(v, ",")
		}
		f.Scanner = r.URL.Query().Get("scanner")
		f.Search = r.URL.Query().Get("q")
		f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
		f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
		out, err := s.Findings.List(r.Context(), f)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func getFinding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "finding_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		f, err := s.Findings.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, f)
	}
}

func patchFinding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "finding_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			Status     string `json:"status"`
			AssigneeID string `json:"assignee_id"`
			Note       string `json:"note"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		if req.Status != "" {
			if err := s.Findings.Transition(r.Context(), &identity.UserID, id, req.Status, req.Note); err != nil {
				badRequest(w, err.Error())
				return
			}
		}
		if req.AssigneeID != "" {
			aid, err := uuid.Parse(req.AssigneeID)
			if err != nil {
				badRequest(w, "bad assignee_id")
				return
			}
			if err := s.Findings.Assign(r.Context(), &identity.UserID, id, aid); err != nil {
				internalErr(w, err)
				return
			}
		}
		f, err := s.Findings.Get(r.Context(), id)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, f)
	}
}

// ----- Evidence ----------------------------------------------------------

func evidenceMeta(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		e, err := s.Vault.GetMeta(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func signedDownloadURL(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		base := schemeAndHost(r)
		u, err := s.Vault.SignedDownloadURL(r.Context(), id, base)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, u)
	}
}

func downloadEvidence(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		expStr := r.URL.Query().Get("exp")
		sig := r.URL.Query().Get("sig")
		expUnix, _ := strconv.ParseInt(expStr, 10, 64)
		if !s.Vault.VerifySignature(id, expUnix, sig) {
			writeJSON(w, http.StatusForbidden,
				map[string]string{"error": "invalid or expired signature"})
			return
		}
		identity, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if identity != nil {
			actor = &identity.UserID
		}
		body, ev, err := s.Vault.Read(r.Context(), id, actor, clientIP(r), r.UserAgent())
		if err != nil {
			internalErr(w, err)
			return
		}
		w.Header().Set("Content-Type", ev.ContentType)
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%s-%s", ev.EvidenceType, ev.ID))
		_, _ = io.Copy(w, byteReader(body))
	}
}

// ----- Retesting ---------------------------------------------------------

func requestRetest(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			FindingID string `json:"finding_id"`
			Note      string `json:"note"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		fid, err := uuid.Parse(req.FindingID)
		if err != nil {
			badRequest(w, "finding_id required")
			return
		}
		identity, _ := auth.FromContext(r.Context())
		id, err := s.Retests.Request(r.Context(), retesting.RequestInput{
			FindingID: fid, RequestedBy: &identity.UserID, Note: req.Note,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
	}
}

func recordRetestResult(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "retest_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			ScanJobID string `json:"scan_job_id"`
			Outcome   string `json:"outcome"`
			Summary   string `json:"summary"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		var sj *uuid.UUID
		if req.ScanJobID != "" {
			s, err := uuid.Parse(req.ScanJobID)
			if err == nil {
				sj = &s
			}
		}
		if err := s.Retests.RecordResult(r.Context(), retesting.ResultInput{
			RetestRequestID: id, ScanJobID: sj, Outcome: req.Outcome,
			Summary: req.Summary, DecidedBy: &identity.UserID,
		}); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
	}
}

func listRetestsForFinding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fid, err := uuidParam(r, "finding_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		out, err := s.Retests.ListByFinding(r.Context(), fid)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

// ----- Reports -----------------------------------------------------------

type generateReportReq struct {
	PartnerID    string   `json:"partner_id"`
	TenantID     string   `json:"tenant_id"`
	EngagementID string   `json:"engagement_id"`
	ReportType   string   `json:"report_type"`
	Title        string   `json:"title"`
	Formats      []string `json:"formats"`
}

func generateReport(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req generateReportReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		partnerID, _ := uuid.Parse(req.PartnerID)
		tenantID, _ := uuid.Parse(req.TenantID)
		engagementID, err := uuid.Parse(req.EngagementID)
		if err != nil {
			badRequest(w, "engagement_id required")
			return
		}
		report, err := s.Reports.Generate(r.Context(), reporting.GenerateInput{
			PlatformID: identity.PlatformID, PartnerID: partnerID, TenantID: tenantID,
			EngagementID: engagementID, ReportType: req.ReportType,
			Title: req.Title, Formats: req.Formats, GeneratedBy: &identity.UserID,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, report)
	}
}

func getReport(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "report_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		report, err := s.Reports.Get(r.Context(), id)
		if err != nil {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// ----- Integrations ------------------------------------------------------

func listIntegrations(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tid, pid *uuid.UUID
		if v := r.URL.Query().Get("tenant_id"); v != "" {
			id, err := uuid.Parse(v)
			if err == nil {
				tid = &id
			}
		}
		if v := r.URL.Query().Get("partner_id"); v != "" {
			id, err := uuid.Parse(v)
			if err == nil {
				pid = &id
			}
		}
		out, err := s.Integrations.List(r.Context(), tid, pid)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func createIntegration(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		itype := chi.URLParam(r, "type")
		var req struct {
			TenantID    string         `json:"tenant_id"`
			PartnerID   string         `json:"partner_id"`
			Name        string         `json:"name"`
			Config      map[string]any `json:"config"`
			SecretRef   string         `json:"secret_ref"`
			EventFilter []string       `json:"event_filter"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		var tid, pid *uuid.UUID
		if req.TenantID != "" {
			id, _ := uuid.Parse(req.TenantID)
			tid = &id
		}
		if req.PartnerID != "" {
			id, _ := uuid.Parse(req.PartnerID)
			pid = &id
		}
		id, err := s.Integrations.Create(r.Context(), integrations.CreateInput{
			TenantID: tid, PartnerID: pid, Type: itype, Name: req.Name,
			Config: req.Config, SecretRef: req.SecretRef,
			EventFilter: req.EventFilter, CreatedBy: &identity.UserID,
		})
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
	}
}

// ----- Dashboards --------------------------------------------------------

func execDashboard(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		out, err := s.Dashboards.Executive(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func techDashboard(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuid.Parse(r.URL.Query().Get("tenant_id"))
		if err != nil {
			badRequest(w, "tenant_id required")
			return
		}
		out, err := s.Dashboards.Technical(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func partnerDashboard(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuid.Parse(r.URL.Query().Get("partner_id"))
		if err != nil {
			badRequest(w, "partner_id required")
			return
		}
		out, err := s.Dashboards.Partner(r.Context(), partnerID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// ----- Audit -------------------------------------------------------------

func listAudit(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, _ := auth.FromContext(r.Context())
		args := []any{identity.PlatformID}
		q := `SELECT id, event, actor_type, actor_id, target_type, target_id,
		             tenant_id, partner_id, occurred_at, payload
		        FROM audit_logs WHERE platform_id=$1`
		if v := r.URL.Query().Get("tenant_id"); v != "" {
			id, err := uuid.Parse(v)
			if err == nil {
				q += fmt.Sprintf(" AND tenant_id=$%d", len(args)+1)
				args = append(args, id)
			}
		}
		if v := r.URL.Query().Get("event"); v != "" {
			q += fmt.Sprintf(" AND event=$%d", len(args)+1)
			args = append(args, v)
		}
		q += " ORDER BY occurred_at DESC LIMIT 200"
		rows, err := s.Pool.Query(r.Context(), q, args...)
		if err != nil {
			internalErr(w, err)
			return
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var (
				id              int64
				event, actor    string
				actorID         *uuid.UUID
				tType, tID      *string
				tenantID, partID *uuid.UUID
				occ             time.Time
				payload         string // TEXT since migration 0012
			)
			if err := rows.Scan(&id, &event, &actor, &actorID, &tType, &tID,
				&tenantID, &partID, &occ, &payload); err != nil {
				internalErr(w, err)
				return
			}
			var pl any
			_ = json.Unmarshal([]byte(payload), &pl)
			out = append(out, map[string]any{
				"id": id, "event": event, "actor_type": actor, "actor_id": actorID,
				"target_type": tType, "target_id": tID, "tenant_id": tenantID,
				"partner_id": partID, "occurred_at": occ, "payload": pl,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func verifyAudit(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brokenAt, err := s.Audit.Verify(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"chain_valid": brokenAt == 0, "broken_at_id": brokenAt,
		})
	}
}

// ----- helpers ------------------------------------------------------------

func schemeAndHost(r *http.Request) string {
	scheme := "https"
	if r.Header.Get("X-Forwarded-Proto") != "" {
		scheme = r.Header.Get("X-Forwarded-Proto")
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// orchestratorPublicKey serves the RSA SubjectPublicKeyInfo PEM that scanner
// workers and internal agents use to verify per-job signatures.
func orchestratorPublicKey(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Signer == nil {
			internalErr(w, errors.New("orchestrator signer not configured"))
			return
		}
		pem, err := s.Signer.PublicKeyPEM()
		if err != nil {
			internalErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(pem))
	}
}

// rotateAgentCert revokes the agent's current certificate and issues a
// fresh one-time enrollment token. The agent's update channel detects the
// rotation (cert_status='expiring' → 'revoked') and re-enrolls via the
// agent-gateway with the new token.
func rotateAgentCert(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())

		// Revoke active cert + flip agent into pending-enroll. The agent's
		// next heartbeat-ack will see the status change and trigger
		// re-enrollment.
		ctx := r.Context()
		if _, err := s.Pool.Exec(ctx, `
			UPDATE agent_certificates SET revoked_at = now()
			 WHERE agent_id = $1 AND revoked_at IS NULL`, id); err != nil {
			internalErr(w, err)
			return
		}
		if _, err := s.Pool.Exec(ctx, `
			UPDATE agents
			   SET status='pending', cert_status='revoked', updated_at=now()
			 WHERE id=$1`, id); err != nil {
			internalErr(w, err)
			return
		}

		// Issue a new enrollment token via the agents service (re-uses the
		// same bcrypt token machinery that initial provisioning uses).
		tok, err := agents.IssueRotationToken(ctx, s.Pool, id, &identity.UserID)
		if err != nil {
			internalErr(w, err)
			return
		}

		// Audit + bus.
		platID := identity.PlatformID
		_ = s.Audit.Record(ctx, audit.Entry{
			PlatformID: platID, ActorID: &identity.UserID,
			Event: audit.EventAgentCertRotated, TargetType: "agent",
			TargetID: id.String(),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"agent_id":         id,
			"enrollment_token": tok,
			"note":             "Cert revoked. Agent will re-enroll on next update poll.",
		})
	}
}

type byteReadCloser struct{ p []byte }

func (b *byteReadCloser) Read(p []byte) (int, error) {
	if len(b.p) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.p)
	b.p = b.p[n:]
	return n, nil
}
func (b *byteReadCloser) Close() error { return nil }

func byteReader(b []byte) *byteReadCloser { return &byteReadCloser{p: b} }

// ensure audit pkg referenced in case future expansion adds direct event consts.
var _ = audit.EventEmergencyStop

// jwtClaimsRegistered builds default RegisteredClaims for a dev token.
func jwtClaimsRegistered(sub string, ttl time.Duration) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Issuer:    "vaultscan-dev",
	}
}
