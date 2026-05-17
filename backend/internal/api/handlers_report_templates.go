// handlers_report_templates.go — CRUD on partner-uploaded report
// templates. Routes (under /api/v1/partners/{partner_id}/report-templates,
// all manage_branding gated):
//
//	GET    /                    — list all overrides for a partner
//	PUT    /{report_type}       — upsert an override
//	DELETE /{report_type}       — drop the override (fall back to default)
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/zaishield/vaultscan/backend/internal/reporting"
)

func listPartnerReportTemplates(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		out, err := s.Reports.ListPartnerTemplates(r.Context(), partnerID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

type upsertReportTemplateReq struct {
	Body      string   `json:"body"`       // html/template source
	Sections  []string `json:"sections"`   // optional ordered section ids
	CoverURL  string   `json:"cover_url"`  // optional PDF cover override
	Footer    string   `json:"footer"`     // optional footer override
	Watermark string   `json:"watermark"`  // optional watermark override
}

func upsertPartnerReportTemplate(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		reportType := chi.URLParam(r, "report_type")
		if reportType == "" {
			badRequest(w, "report_type required")
			return
		}
		var req upsertReportTemplateReq
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		// Defensive cap on body size — html/template will happily
		// parse a 100 MB blob and burn memory before any render.
		// 256 KiB covers any realistic partner template (the
		// default is ~3 KiB).
		const maxBody = 256 * 1024
		if len(req.Body) > maxBody {
			badRequest(w, "template body exceeds 256 KiB")
			return
		}
		if err := s.Reports.UpsertPartnerTemplate(r.Context(), reporting.UpsertPartnerTemplateInput{
			PartnerID:  partnerID,
			ReportType: reportType,
			Body:       req.Body,
			Sections:   req.Sections,
			CoverURL:   req.CoverURL,
			Footer:     req.Footer,
			Watermark:  req.Watermark,
		}); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func deletePartnerReportTemplate(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		reportType := chi.URLParam(r, "report_type")
		if reportType == "" {
			badRequest(w, "report_type required")
			return
		}
		if err := s.Reports.DeletePartnerTemplate(r.Context(), partnerID, reportType); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}
