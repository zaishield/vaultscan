// §33 Customer feedback endpoints. Single submit endpoint + admin
// triage surface; per-user "do not show again" for NPS prompts.
package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

func submitFeedback(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		var req struct {
			Category  string `json:"category"`
			Severity  string `json:"severity"`
			Rating    *int   `json:"rating,omitempty"` // NPS 0..10
			Title     string `json:"title"`
			Body      string `json:"body"`
			Feature   string `json:"feature"`
			PortalURL string `json:"portal_url"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		validCats := map[string]bool{
			"nps": true, "bug": true, "feature": true,
			"thumbs_up": true, "thumbs_down": true, "other": true,
		}
		if !validCats[req.Category] {
			badRequest(w, "category must be one of: nps, bug, feature, thumbs_up, thumbs_down, other")
			return
		}
		if req.Severity == "" {
			req.Severity = "normal"
		}
		if req.Title == "" {
			req.Title = strings.ToUpper(req.Category) + " feedback"
		}
		// NPS rating validation.
		if req.Category == "nps" {
			if req.Rating == nil || *req.Rating < 0 || *req.Rating > 10 {
				badRequest(w, "NPS rating must be 0..10")
				return
			}
		}
		var fbID uuid.UUID
		err = s.Pool.QueryRow(r.Context(), `
			INSERT INTO customer_feedback(tenant_id, user_id, category, severity,
			    rating, title, body, feature, portal_url, user_agent)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8,''),
			        NULLIF($9,''), NULLIF($10,''))
			RETURNING id`,
			id.TenantID, id.UserID, req.Category, req.Severity, req.Rating,
			req.Title, req.Body, req.Feature, req.PortalURL,
			r.Header.Get("User-Agent")).Scan(&fbID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": fbID})
	}
}

func listFeedback(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		if status == "" {
			status = "new"
		}
		rows, err := s.Pool.Query(r.Context(), `
			SELECT id, tenant_id, user_id, category, severity, rating, title,
			       body, feature, status, created_at
			  FROM customer_feedback
			 WHERE status = $1
			 ORDER BY (severity='urgent') DESC, (severity='high') DESC,
			          created_at DESC LIMIT 200`, status)
		if err != nil {
			internalErr(w, err)
			return
		}
		defer rows.Close()
		type row struct {
			ID        uuid.UUID `json:"id"`
			TenantID  *uuid.UUID `json:"tenant_id"`
			UserID    *uuid.UUID `json:"user_id"`
			Category  string    `json:"category"`
			Severity  string    `json:"severity"`
			Rating    *int      `json:"rating,omitempty"`
			Title     string    `json:"title"`
			Body      string    `json:"body"`
			Feature   *string   `json:"feature,omitempty"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		}
		var out []row
		for rows.Next() {
			var rr row
			if err := rows.Scan(&rr.ID, &rr.TenantID, &rr.UserID, &rr.Category,
				&rr.Severity, &rr.Rating, &rr.Title, &rr.Body, &rr.Feature,
				&rr.Status, &rr.CreatedAt); err != nil {
				continue
			}
			out = append(out, rr)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func triageFeedback(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fbID, err := uuidParam(r, "feedback_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			Status     string `json:"status"`
			Resolution string `json:"resolution"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if req.Status != "triaged" && req.Status != "in_progress" &&
			req.Status != "resolved" && req.Status != "dismissed" {
			badRequest(w, "status must be triaged|in_progress|resolved|dismissed")
			return
		}
		id, _ := auth.FromContext(r.Context())
		resolvedAt := "NULL::timestamptz"
		if req.Status == "resolved" || req.Status == "dismissed" {
			resolvedAt = "now()"
		}
		tag, err := s.Pool.Exec(r.Context(), `
			UPDATE customer_feedback
			   SET status = $2, triaged_by = $3,
			       resolution = NULLIF($4,''),
			       resolved_at = `+resolvedAt+`
			 WHERE id = $1`, fbID, req.Status, id.UserID, req.Resolution)
		if err != nil {
			internalErr(w, err)
			return
		}
		if tag.RowsAffected() == 0 {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": req.Status})
	}
}

// dismissNPSPrompt records a "don't ask me again" for NPS surveys
// for `cooldownDays` days. Soft-implemented via a prompt row.
func dismissNPSPrompt(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		_, err = s.Pool.Exec(r.Context(), `
			INSERT INTO customer_feedback_prompts(user_id, kind, sent_at, dismissed_at)
			VALUES ($1, 'nps', now(), now())`, id.UserID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "dismissed"})
	}
}
