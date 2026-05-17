// §24 Mobile-portal handlers. Thin surface — mobile clients (iOS +
// Android) hit these to enroll their push tokens, read a slimmed-
// down dashboard, ack alerts they were paged about, and (in
// emergencies) trigger the platform-wide scan stop.
//
// Every endpoint is auth-gated like the rest of the API. The
// mobile-client OAuth scope is enforced by the realm's
// vaultscan-mobile client, so a stolen mobile token can't move past
// these routes into administrative surfaces.
package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

func enrollMobileDevice(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		var req struct {
			Platform   string `json:"platform"`    // ios | android
			PushToken  string `json:"push_token"`
			AppVersion string `json:"app_version"`
			OSVersion  string `json:"os_version"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if req.Platform != "ios" && req.Platform != "android" {
			badRequest(w, "platform must be ios or android")
			return
		}
		if req.PushToken == "" {
			badRequest(w, "push_token required")
			return
		}
		var deviceID uuid.UUID
		err = s.Pool.QueryRow(r.Context(), `
			INSERT INTO mobile_device_tokens(user_id, platform, push_token,
			    app_version, os_version)
			VALUES ($1, $2, $3, NULLIF($4,''), NULLIF($5,''))
			ON CONFLICT (user_id, push_token) DO UPDATE
			   SET last_seen_at = now(),
			       app_version  = COALESCE(NULLIF(EXCLUDED.app_version,''),
			                               mobile_device_tokens.app_version),
			       os_version   = COALESCE(NULLIF(EXCLUDED.os_version,''),
			                               mobile_device_tokens.os_version),
			       revoked_at = NULL
			RETURNING id`,
			id.UserID, req.Platform, req.PushToken, req.AppVersion, req.OSVersion).
			Scan(&deviceID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device_id": deviceID})
	}
}

func revokeMobileDevice(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceID, err := uuidParam(r, "device_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		// Restrict to own device.
		tag, err := s.Pool.Exec(r.Context(), `
			UPDATE mobile_device_tokens SET revoked_at = now()
			 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
			deviceID, id.UserID)
		if err != nil {
			internalErr(w, err)
			return
		}
		if tag.RowsAffected() == 0 {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
	}
}

func mobileDashboard(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		// Slimmed-down executive-style summary — mobile cares about
		// counts + the top-5 critical findings, not the full set.
		var summary struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			SLABreached int `json:"sla_breached"`
			OnlineAgents int `json:"online_agents"`
		}
		_ = s.Pool.QueryRow(r.Context(), `
			SELECT
			  (SELECT count(*) FROM findings WHERE tenant_id=$1 AND severity='critical'
			    AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
			  (SELECT count(*) FROM findings WHERE tenant_id=$1 AND severity='high'
			    AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
			  (SELECT count(*) FROM findings WHERE tenant_id=$1
			    AND sla_breached_at IS NOT NULL
			    AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
			  (SELECT count(*) FROM agents WHERE tenant_id=$1 AND status='online')`,
			tenantID).Scan(&summary.Critical, &summary.High, &summary.SLABreached, &summary.OnlineAgents)

		type topFinding struct {
			ID       string  `json:"id"`
			Title    string  `json:"title"`
			Severity string  `json:"severity"`
			Endpoint string  `json:"endpoint"`
			LastSeen string  `json:"last_seen"`
		}
		rows, err := s.Pool.Query(r.Context(), `
			SELECT id, title, severity, COALESCE(affected_endpoint,''), last_seen
			  FROM findings
			 WHERE tenant_id=$1 AND severity IN ('critical','high')
			   AND status NOT IN ('closed','remediated','retest_passed','false_positive')
			 ORDER BY (severity='critical') DESC, last_seen DESC LIMIT 5`, tenantID)
		var top []topFinding
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f topFinding
				var t time.Time
				if err := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.Endpoint, &t); err != nil {
					continue
				}
				f.LastSeen = t.UTC().Format(time.RFC3339)
				top = append(top, f)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"summary": summary,
			"top_findings": top,
		})
	}
}

func mobileAckAlert(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		var req struct {
			FindingID      string `json:"finding_id"`
			NotificationID string `json:"notification_id"`
			DeviceID       string `json:"device_id"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		var fid, nid, did *uuid.UUID
		if v, err := uuid.Parse(req.FindingID); err == nil {
			fid = &v
		}
		if v, err := uuid.Parse(req.NotificationID); err == nil {
			nid = &v
		}
		if v, err := uuid.Parse(req.DeviceID); err == nil {
			did = &v
		}
		var ackID uuid.UUID
		err = s.Pool.QueryRow(r.Context(), `
			INSERT INTO mobile_alert_acks(user_id, finding_id, notification_id, device_id)
			VALUES ($1, $2, $3, $4) RETURNING id`,
			id.UserID, fid, nid, did).Scan(&ackID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ack_id": ackID})
	}
}

func mobileEmergencyStop(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		if !id.MFAVerified {
			writeJSONError(w, http.StatusForbidden, "mfa_required",
				"mobile emergency-stop requires MFA")
			return
		}
		var req struct {
			TenantID string `json:"tenant_id"`
			Reason   string `json:"reason"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		tid, terr := auth.AuthorizeTargetTenant(id, req.TenantID)
		if terr != nil {
			forbidden(w, terr.Error())
			return
		}
		scope := scanorch.EmergencyScope{TenantID: &tid}
		n, err := s.ScanOrch.EmergencyStop(r.Context(), &id.UserID, scope)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stopped": n, "reason": req.Reason})
	}
}
