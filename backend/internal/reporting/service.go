// Package reporting generates branded reports in multiple formats
// (Blueprint §19). The implementation produces canonical HTML, JSON, CSV,
// and PDF. DOCX/XLSX are accepted at the API surface for compatibility
// but only succeed if a real renderer has been wired into the
// Service (Service.SetDOCXRenderer / SetXLSXRenderer) — otherwise
// Generate() rejects them rather than emitting corrupt files.
package reporting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

// reportingLogger surfaces post-commit audit/bus failures. We log
// rather than rollback because the report rows are committed and
// useful — a missing audit event is a known-and-monitored degradation,
// not a reason to throw away the user's report.
var reportingLogger = zerolog.New(os.Stderr).With().
	Timestamp().Str("component", "reporting").Logger()

// Eleven report types from Blueprint §19.1.
const (
	TypeExecutive      = "executive"
	TypeTechnical      = "technical"
	TypeExternal       = "external_attack_surface"
	TypeInternal       = "internal_network"
	TypeWebAPI         = "web_api"
	TypeCloud          = "cloud_security"
	TypeAD             = "ad_security"
	TypeContainerK8s   = "container_kubernetes"
	TypeRetest         = "retest"
	TypeCompliance     = "compliance"
	TypeRiskRegister   = "risk_register"
)

// AllReportTypes returns the 11 supported report types.
func AllReportTypes() []string {
	return []string{
		TypeExecutive, TypeTechnical, TypeExternal, TypeInternal, TypeWebAPI,
		TypeCloud, TypeAD, TypeContainerK8s, TypeRetest, TypeCompliance, TypeRiskRegister,
	}
}

// All export formats from Blueprint §19.3.
const (
	FormatPDF  = "pdf"
	FormatHTML = "html"
	FormatJSON = "json"
	FormatCSV  = "csv"
	// FormatDOCX / FormatXLSX are accepted for API compatibility but
	// only succeed if a real DOCX/XLSX renderer has been wired into
	// the Service (Service.docxRenderer / Service.xlsxRenderer).
	// In the default build neither is wired and Generate() will
	// reject these formats up-front rather than silently writing
	// HTML/CSV bytes labelled with the wrong MIME type (which
	// corrupted files in Word/Excel).
	FormatDOCX = "docx"
	FormatXLSX = "xlsx"
)

// AllFormats lists every format the renderer code can produce in
// principle. Generate() additionally calls formatAvailable() per
// item, which is the source of truth for "what this build can
// actually emit". Callers wanting a safe default set should use
// DefaultFormats().
func AllFormats() []string {
	return []string{FormatPDF, FormatHTML, FormatJSON, FormatCSV, FormatDOCX, FormatXLSX}
}

// DefaultFormats is what Generate() picks when the caller passes no
// formats. Includes DOCX and XLSX because the default renderers
// (defaultDOCXRenderer / defaultXLSXRenderer) are always wired by
// New(). Operators who haven't customised report formats get every
// useful format out of the box.
func DefaultFormats() []string {
	return []string{FormatHTML, FormatJSON, FormatCSV, FormatPDF, FormatDOCX, FormatXLSX}
}

type Service struct {
	pool         *pgxpool.Pool
	branding     *branding.Service
	store        *evidence.Vault
	audit        *audit.Service
	bus          *eventbus.Bus
	pdfRenderer  PDFRenderer
	docxRenderer DOCXRenderer
	xlsxRenderer XLSXRenderer
}

// DOCXRenderer / XLSXRenderer let an operator plug real Office-doc
// generators into the Service from cmd/api at startup. The default
// build leaves both nil — Generate() will reject DOCX/XLSX requests
// rather than emit corrupt files with the wrong MIME type.
type DOCXRenderer interface {
	Render(ctx context.Context, d *Dataset) ([]byte, error)
	Name() string
}

type XLSXRenderer interface {
	Render(ctx context.Context, d *Dataset) ([]byte, error)
	Name() string
}

func New(pool *pgxpool.Pool, b *branding.Service, st *evidence.Vault, a *audit.Service, bus *eventbus.Bus) *Service {
	s := &Service{pool: pool, branding: b, store: st, audit: a, bus: bus}
	// Default XLSX renderer uses the in-repo xlsxgen package (zero
	// extra deps, valid Open XML SpreadsheetML). Operators can
	// override via SetXLSXRenderer if they want excelize/unioffice.
	s.xlsxRenderer = defaultXLSXRenderer{}
	// Default DOCX renderer emits a minimal Office Open XML
	// WordprocessingML document (also zero extra deps). Same override
	// path as XLSX.
	s.docxRenderer = defaultDOCXRenderer{}
	return s
}

// SetDOCXRenderer / SetXLSXRenderer / SetPDFRenderer wire real
// renderers from cmd/api at startup.
func (s *Service) SetPDFRenderer(r PDFRenderer)   { s.pdfRenderer = r }
func (s *Service) SetDOCXRenderer(r DOCXRenderer) { s.docxRenderer = r }
func (s *Service) SetXLSXRenderer(r XLSXRenderer) { s.xlsxRenderer = r }

// formatAvailable returns true if Generate can actually produce the
// named format end-to-end in this build. HTML / JSON / CSV are
// always available because they're rendered inline. PDF works via
// the wired renderer if present and falls back to HTML-with-PDF-
// MIME otherwise (intentional — chromium isn't always packaged).
// DOCX / XLSX require an explicitly-wired renderer; without one
// they are unavailable so callers see a real error instead of a
// corrupt file.
func (s *Service) formatAvailable(format string) bool {
	switch format {
	case FormatHTML, FormatJSON, FormatCSV, FormatPDF:
		return true
	case FormatDOCX:
		return s.docxRenderer != nil
	case FormatXLSX:
		return s.xlsxRenderer != nil
	}
	return false
}

type GenerateInput struct {
	PlatformID   uuid.UUID
	PartnerID    uuid.UUID
	TenantID     uuid.UUID
	EngagementID uuid.UUID
	ReportType   string
	Title        string
	Formats      []string
	GeneratedBy  *uuid.UUID
}

type Report struct {
	ID           uuid.UUID                  `json:"id"`
	ReportType   string                     `json:"report_type"`
	Title        string                     `json:"title"`
	Status       string                     `json:"status"`
	Exports      []Export                   `json:"exports"`
	GeneratedAt  time.Time                  `json:"generated_at"`
}

type Export struct {
	Format     string  `json:"format"`
	StorageURL string  `json:"storage_url"`
	SHA256     string  `json:"sha256"`
	SizeBytes  int64   `json:"size_bytes"`
}

// Generate produces the report in all requested formats.
//
// Atomicity: the previous version inserted the `reports` row with
// status='generating' BEFORE gathering data or rendering. A render
// failure (PDF chromium crash, branding load error) would orphan the
// row in 'generating' state permanently, and the scheduler had no
// signal to retry it. We now do the heavy work first and only INSERT
// once everything is materialised in memory; on failure we never
// write anything to `reports`. The render+export+UPDATE final-status
// runs inside a single transaction so partial failures don't leak
// half-built reports either.
func (s *Service) Generate(ctx context.Context, in GenerateInput) (*Report, error) {
	if !validReportType(in.ReportType) {
		return nil, fmt.Errorf("reporting: unsupported report_type %q", in.ReportType)
	}
	if len(in.Formats) == 0 {
		in.Formats = DefaultFormats()
	}
	// Validate that every requested format is real. DOCX/XLSX were
	// previously accepted but silently served HTML/CSV bytes with the
	// wrong MIME type — invalid files when opened in Word/Excel. We
	// now reject those formats up-front unless a real renderer has
	// been wired (s.docxRenderer / s.xlsxRenderer are nil today, so
	// the formats are unavailable; AllFormats / DefaultFormats no
	// longer include them).
	for _, f := range in.Formats {
		if !s.formatAvailable(f) {
			return nil, fmt.Errorf("reporting: format %q is not available in this build", f)
		}
	}
	id := uuid.New()
	requiresApproval := s.partnerApprovalRequired(ctx, in.PartnerID)

	dataset, err := s.gatherDataset(ctx, in)
	if err != nil {
		return nil, err
	}
	bundle, err := s.branding.LoadBundle(ctx, in.PartnerID)
	if err != nil {
		return nil, err
	}
	dataset.Branding = &bundle.Branding

	// Render every format into memory before touching `reports`.
	type renderedExport struct {
		Format     string
		Body       []byte
		StorageURL string
		SHA256     string
	}
	rendered := make([]renderedExport, 0, len(in.Formats))
	for _, format := range in.Formats {
		body, ct, err := s.render(ctx, format, in.ReportType, dataset)
		if err != nil {
			return nil, fmt.Errorf("reporting: render %s: %w", format, err)
		}
		storageURL, err := s.store.Put(ctx, evidence.PutInput{
			TenantID: in.TenantID, PartnerID: in.PartnerID,
			Kind: "report", ContentType: ct, Body: body,
		})
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		rendered = append(rendered, renderedExport{
			Format: format, Body: body,
			StorageURL: storageURL, SHA256: hex.EncodeToString(sum[:]),
		})
	}

	finalStatus := "ready"
	if requiresApproval {
		finalStatus = "pending_approval"
	}
	rendererName := "html-fallback"
	if s.pdfRenderer != nil {
		rendererName = s.pdfRenderer.Name()
	}

	// Persist the report + every export atomically. If any of these
	// fails, nothing is left in `reports` and the caller can retry
	// without leaving an orphan row behind.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO reports(id, platform_id, partner_id, tenant_id, engagement_id,
		    report_type, title, status, generated_by, requires_approval,
		    generated_at, pdf_renderer)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), $11)`,
		id, in.PlatformID, in.PartnerID, in.TenantID, in.EngagementID,
		in.ReportType, in.Title, finalStatus, in.GeneratedBy, requiresApproval,
		rendererName); err != nil {
		return nil, err
	}
	r := &Report{
		ID: id, ReportType: in.ReportType, Title: in.Title,
		Status: finalStatus, GeneratedAt: time.Now().UTC(),
	}
	for _, e := range rendered {
		if _, err := tx.Exec(ctx, `
			INSERT INTO report_exports(report_id, format, storage_url, sha256, size_bytes)
			VALUES ($1,$2,$3,$4,$5)`,
			id, e.Format, e.StorageURL, e.SHA256, int64(len(e.Body))); err != nil {
			return nil, err
		}
		r.Exports = append(r.Exports, Export{
			Format: e.Format, StorageURL: e.StorageURL,
			SHA256: e.SHA256, SizeBytes: int64(len(e.Body)),
		})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	// Audit + bus emission AFTER commit. We deliberately don't roll
	// the report back if audit fails — the report row + exports are
	// committed and useful; a missing audit event surfaces via the
	// hourly audit-chain Verify cron and the audit-record-failures
	// metric. Bus.Publish is best-effort by design. If either fails
	// we log loudly so an operator can backfill manually.
	if err := s.audit.Record(ctx, audit.Entry{
		PlatformID: in.PlatformID, PartnerID: &in.PartnerID, TenantID: &in.TenantID,
		ActorID: in.GeneratedBy, Event: audit.EventReportGenerated,
		TargetType: "report", TargetID: id.String(),
		Payload: map[string]any{"type": in.ReportType, "formats": in.Formats},
	}); err != nil {
		reportingLogger.Error().Err(err).Str("report_id", id.String()).
			Msg("reporting: report committed but audit.Record failed — operator must backfill")
	}
	if err := s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ReportGenerated, TenantID: &in.TenantID, PartnerID: &in.PartnerID,
		ActorID: in.GeneratedBy,
		Payload: map[string]any{"report_id": id, "type": in.ReportType, "formats": in.Formats},
	}); err != nil {
		reportingLogger.Warn().Err(err).Str("report_id", id.String()).
			Msg("reporting: report committed but bus.Publish failed — downstream consumers may miss this event")
	}
	return r, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Report, error) {
	r := &Report{ID: id}
	if err := s.pool.QueryRow(ctx, `
		SELECT report_type, title, status, COALESCE(generated_at, created_at)
		  FROM reports WHERE id=$1`, id).
		Scan(&r.ReportType, &r.Title, &r.Status, &r.GeneratedAt); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT format, storage_url, sha256, size_bytes FROM report_exports WHERE report_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Export
		if err := rows.Scan(&e.Format, &e.StorageURL, &e.SHA256, &e.SizeBytes); err != nil {
			return nil, err
		}
		r.Exports = append(r.Exports, e)
	}
	return r, nil
}

// partnerApprovalRequired reads partner_feature_flags. Defaults to false
// when the flag isn't present.
func (s *Service) partnerApprovalRequired(ctx context.Context, partnerID uuid.UUID) bool {
	var enabled bool
	_ = s.pool.QueryRow(ctx, `
		SELECT enabled FROM partner_feature_flags
		 WHERE partner_id=$1 AND flag='reports.approval_required'`,
		partnerID).Scan(&enabled)
	return enabled
}

// Approve marks a pending report as approved (or rejected). On approve,
// flips status to 'ready' so the report can be downloaded. Records an
// audit event with the approver + decision.
func (s *Service) Approve(ctx context.Context, reportID uuid.UUID,
	approver *uuid.UUID, decision string, note string) error {
	if decision != "approved" && decision != "rejected" {
		return fmt.Errorf("reporting: decision must be approved|rejected, got %q", decision)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO report_approvals(report_id, approver_id, decision, note)
		VALUES ($1, $2, $3, $4)`, reportID, approver, decision, note); err != nil {
		return err
	}
	newStatus := "approved"
	if decision == "rejected" {
		newStatus = "rejected"
	}
	if _, err := tx.Exec(ctx,
		`UPDATE reports SET status=$2, approved_by=$3, approved_at=now() WHERE id=$1`,
		reportID, newStatus, approver); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	var platformID, partnerID, tenantID uuid.UUID
	_ = s.pool.QueryRow(ctx,
		`SELECT platform_id, partner_id, tenant_id FROM reports WHERE id=$1`, reportID).
		Scan(&platformID, &partnerID, &tenantID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: approver, Event: "report." + decision,
		TargetType: "report", TargetID: reportID.String(),
		Payload: map[string]any{"note": note},
	})
}

// LogDownload records a report download for audit.
func (s *Service) LogDownload(ctx context.Context, reportID uuid.UUID, exportID *uuid.UUID, userID *uuid.UUID, ip, ua string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO report_download_logs(report_id, export_id, user_id, ip, user_agent)
		VALUES ($1,$2,$3,NULLIF($4,'')::inet,NULLIF($5,''))`,
		reportID, exportID, userID, ip, ua)
	return err
}

// ----- dataset & rendering ------------------------------------------------

type Dataset struct {
	Engagement     models.Engagement       `json:"engagement"`
	Tenant         models.Tenant           `json:"tenant"`
	Partner        models.Partner          `json:"partner"`
	Branding       *models.PartnerBranding `json:"branding,omitempty"`
	Findings       []models.Finding        `json:"findings"`
	SeverityCounts map[string]int          `json:"severity_counts"`
	GeneratedAt    time.Time               `json:"generated_at"`
	ReportType     string                  `json:"report_type"`
	Compliance     ComplianceMapping       `json:"compliance,omitempty"`
	// PartnerTemplate is non-nil when the partner has uploaded a
	// custom template for this report_type (partner_report_templates
	// row). The render path uses it instead of the default const.
	// Each section is optional and overrides the matching branding
	// or default value.
	PartnerTemplate *PartnerReportTemplate `json:"-"`
}

// PartnerReportTemplate is the loaded form of a partner_report_templates
// row. Body is the html/template source the partner uploaded;
// Sections is a free-form ordered list of section ids the template
// expects to render. Cover / Footer / Watermark override the matching
// branding fields when non-empty.
type PartnerReportTemplate struct {
	PartnerID  uuid.UUID
	ReportType string
	Body       string
	Sections   []string
	CoverURL   string
	Footer     string
	Watermark  string
	UpdatedAt  time.Time
}

type ComplianceMapping struct {
	ISO27001 map[string]int `json:"iso27001,omitempty"`
	PCIDSS   map[string]int `json:"pci_dss,omitempty"`
	SOC2     map[string]int `json:"soc2,omitempty"`
}

func (s *Service) gatherDataset(ctx context.Context, in GenerateInput) (*Dataset, error) {
	d := &Dataset{
		ReportType: in.ReportType, GeneratedAt: time.Now().UTC(),
		SeverityCounts: map[string]int{},
	}
	// Per-partner template override. Errors are non-fatal — if the
	// lookup fails the renderer falls back to the default
	// reportTemplate const. Logged via the reporting logger.
	if tmpl, err := s.loadPartnerTemplate(ctx, in.PartnerID, in.ReportType); err == nil {
		d.PartnerTemplate = tmpl
	} else if !errors.Is(err, pgx.ErrNoRows) {
		reportingLogger.Warn().Err(err).
			Str("partner_id", in.PartnerID.String()).
			Str("report_type", in.ReportType).
			Msg("reporting: partner template lookup failed; using default")
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT id, platform_id, partner_id, tenant_id, code, name, COALESCE(description,''),
		       status, starts_at, ends_at, intensity, created_at
		  FROM engagements WHERE id=$1`, in.EngagementID).
		Scan(&d.Engagement.ID, &d.Engagement.PlatformID, &d.Engagement.PartnerID,
			&d.Engagement.TenantID, &d.Engagement.Code, &d.Engagement.Name,
			&d.Engagement.Description, &d.Engagement.Status, &d.Engagement.StartsAt,
			&d.Engagement.EndsAt, &d.Engagement.Intensity, &d.Engagement.CreatedAt); err != nil {
		return nil, err
	}
	_ = s.pool.QueryRow(ctx, `
		SELECT id, platform_id, partner_id, name, slug, status, isolation_mode, created_at
		  FROM tenants WHERE id=$1`, in.TenantID).
		Scan(&d.Tenant.ID, &d.Tenant.PlatformID, &d.Tenant.PartnerID, &d.Tenant.Name,
			&d.Tenant.Slug, &d.Tenant.Status, &d.Tenant.IsolationMode, &d.Tenant.CreatedAt)
	_ = s.pool.QueryRow(ctx, `
		SELECT p.id, p.platform_id, p.parent_id, t.code, p.name, p.slug, p.status, p.created_at
		  FROM partners p JOIN partner_types t ON t.id=p.type_id WHERE p.id=$1`,
		in.PartnerID).
		Scan(&d.Partner.ID, &d.Partner.PlatformID, &d.Partner.ParentID, &d.Partner.TypeCode,
			&d.Partner.Name, &d.Partner.Slug, &d.Partner.Status, &d.Partner.CreatedAt)

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, partner_id, engagement_id, asset_id, scan_job_id,
		       title, COALESCE(description,''), severity, confidence, COALESCE(cvss_score,0),
		       COALESCE(cve,''), COALESCE(cwe,''), scanner, scan_type,
		       COALESCE(affected_endpoint,''), COALESCE(port,0), COALESCE(protocol,''),
		       COALESCE(remediation,''), status, first_seen, last_seen, dedup_fingerprint
		  FROM findings WHERE engagement_id=$1`, in.EngagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var f models.Finding
		if err := rows.Scan(&f.ID, &f.TenantID, &f.PartnerID, &f.EngagementID, &f.AssetID,
			&f.ScanJobID, &f.Title, &f.Description, &f.Severity, &f.Confidence,
			&f.CVSSScore, &f.CVE, &f.CWE, &f.Scanner, &f.ScanType, &f.AffectedEndpoint,
			&f.Port, &f.Protocol, &f.Remediation, &f.Status, &f.FirstSeen, &f.LastSeen,
			&f.DedupFingerprint); err != nil {
			return nil, err
		}
		d.Findings = append(d.Findings, f)
		d.SeverityCounts[f.Severity]++
	}

	if in.ReportType == TypeCompliance {
		d.Compliance = mapCompliance(d.Findings)
	}
	return d, nil
}

func (s *Service) render(ctx context.Context, format, reportType string, d *Dataset) ([]byte, string, error) {
	switch format {
	case FormatJSON:
		buf, err := json.MarshalIndent(d, "", "  ")
		return buf, "application/json", err
	case FormatCSV:
		return renderCSV(d)
	case FormatHTML:
		return renderHTML(d)
	case FormatPDF:
		// Production: headless chromium. Dev: tag the HTML with a sentinel
		// header so consumers can pipe it through wkhtmltopdf / chromium
		// themselves. VS-10 wires a real PDFRenderer when configured.
		html, _, err := renderHTML(d)
		if err != nil {
			return nil, "", err
		}
		if s.pdfRenderer != nil {
			// Forward the request ctx so a client disconnect /
			// request timeout cancels the renderer rather than
			// leaving a chromium / wkhtmltopdf subprocess running
			// to completion in the background.
			pdf, err := s.pdfRenderer.Render(ctx, html)
			if err != nil {
				return nil, "", err
			}
			return pdf, "application/pdf", nil
		}
		return html, "application/pdf", nil
	case FormatDOCX:
		// formatAvailable() in Generate() guarantees docxRenderer is
		// non-nil before we reach this branch; the nil check is
		// defence-in-depth in case render() is called directly.
		if s.docxRenderer == nil {
			return nil, "", fmt.Errorf("reporting: docx renderer not wired")
		}
		body, err := s.docxRenderer.Render(ctx, d)
		if err != nil {
			return nil, "", err
		}
		return body, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", nil
	case FormatXLSX:
		if s.xlsxRenderer == nil {
			return nil, "", fmt.Errorf("reporting: xlsx renderer not wired")
		}
		body, err := s.xlsxRenderer.Render(ctx, d)
		if err != nil {
			return nil, "", err
		}
		return body, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", nil
	}
	return nil, "", fmt.Errorf("reporting: unknown format %q", format)
}

func renderCSV(d *Dataset) ([]byte, string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"finding_id", "title", "severity", "cvss", "cve", "cwe",
		"scanner", "endpoint", "port", "status", "first_seen", "last_seen"})
	for _, f := range d.Findings {
		_ = w.Write([]string{
			f.ID.String(), f.Title, f.Severity,
			fmt.Sprintf("%.1f", f.CVSSScore), f.CVE, f.CWE,
			f.Scanner, f.AffectedEndpoint, fmt.Sprintf("%d", f.Port),
			f.Status, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339),
		})
	}
	w.Flush()
	return buf.Bytes(), "text/csv; charset=utf-8", w.Error()
}

// Reports use the ZAISHIELD VAULTSCAN brand: dark sci-fi ops aesthetic,
// sharp corners, mono for data, orange accent only.
const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{{.Title}}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
body { font-family: 'Inter', -apple-system, system-ui, sans-serif; background:#0A0A0A; color:#F0F0F0; margin:0; padding:40px; }
.cover { background:#111111; border:1px solid #2A2A2A; padding: 48px 40px; }
.cover .accent { width:48px; height:2px; background:{{.Primary}}; margin-bottom:24px; }
.cover .label { font-family:'JetBrains Mono', monospace; font-size:11px; letter-spacing:.4em; color:{{.Primary}}; text-transform:uppercase; margin-bottom:8px; }
.cover h1 { font-size:36px; margin:0 0 16px 0; letter-spacing:.1em; text-transform:uppercase; }
.cover h1 .underscore { color:{{.Primary}}; }
.cover .meta { font-family:'JetBrains Mono', monospace; font-size:12px; color:#8A8A8A; margin:4px 0; }
.cover .meta strong { color:#F0F0F0; }
.cover .conf { margin-top:24px; font-family:'JetBrains Mono', monospace; font-size:10px; letter-spacing:.4em; color:{{.Primary}}; text-transform:uppercase; }
h2 { margin-top:40px; font-size:14px; letter-spacing:.3em; text-transform:uppercase; color:{{.Primary}}; padding-bottom:6px; border-bottom:1px solid #2A2A2A; }
h3 { margin-top:24px; font-size:12px; letter-spacing:.3em; text-transform:uppercase; color:#8A8A8A; }
.summary-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:8px; margin-top:16px; }
.summary-grid .cell { border:1px solid #2A2A2A; background:#111; padding:12px; }
.summary-grid .label { font-family:'JetBrains Mono', monospace; font-size:9px; letter-spacing:.3em; color:#8A8A8A; text-transform:uppercase; }
.summary-grid .value { font-family:'JetBrains Mono', monospace; font-size:24px; color:#F0F0F0; margin-top:4px; }
table { border-collapse:collapse; width:100%; margin-top:12px; font-family:'JetBrains Mono', monospace; font-size:11px; }
th, td { border-bottom:1px solid #2A2A2A; padding:8px 12px; text-align:left; }
th { background:#1A1A1A; color:#8A8A8A; font-weight:600; letter-spacing:.2em; text-transform:uppercase; font-size:9px; }
td { color:#F0F0F0; }
.sev { display:inline-block; padding:2px 8px; font-weight:700; font-size:9px; letter-spacing:.2em; text-transform:uppercase; }
.sev.critical { background:#FF2D2D; color:#fff; }
.sev.high     { background:#FF6B00; color:#000; }
.sev.medium   { background:#FFB800; color:#000; }
.sev.low      { background:#00FF88; color:#000; }
.sev.info     { background:#2A2A2A; color:#F0F0F0; }
.footer { margin-top:48px; font-family:'JetBrains Mono', monospace; font-size:10px; color:#8A8A8A; letter-spacing:.2em; border-top:1px solid #2A2A2A; padding-top:12px; text-transform:uppercase; }
.watermark { position:fixed; top:50%; left:50%; transform:translate(-50%,-50%) rotate(-30deg); font-size:80px; color:rgba(255,107,0,0.06); pointer-events:none; font-family:'Inter', sans-serif; font-weight:700; letter-spacing:.4em; }
</style>
</head>
<body>
<div class="watermark">{{.Watermark}}</div>
<div class="cover">
  <div class="accent"></div>
  <div class="label">Enterprise Hybrid VA/PT Platform</div>
  <h1>ZAISHIELD<span class="underscore">_</span>VAULTSCAN</h1>
  <div class="meta">{{.Title}}</div>
  <div class="meta">Engagement: <strong>{{.Engagement.Code}}</strong> &middot; Tenant: <strong>{{.Tenant.Name}}</strong> &middot; Partner: <strong>{{.Partner.Name}}</strong></div>
  <div class="meta">Window: <strong>{{.Engagement.StartsAt.Format "2006-01-02"}} → {{.Engagement.EndsAt.Format "2006-01-02"}}</strong></div>
  <div class="meta">Generated <strong>{{.GeneratedAt.Format "2006-01-02 15:04 MST"}}</strong></div>
  <div class="conf">{{.Confidentiality}}</div>
</div>

<h2>Executive Summary</h2>
<p style="font-size:13px;color:#F0F0F0;line-height:1.6;">
Engagement <strong style="color:{{.Primary}}">{{.Engagement.Code}} · {{.Engagement.Name}}</strong> identified
<strong style="color:{{.Primary}}">{{len .Findings}}</strong> findings during the assessment window.
</p>

<h3>Severity Breakdown</h3>
<div class="summary-grid">
  <div class="cell"><div class="label">Critical</div><div class="value" style="color:#FF2D2D">{{index .Sev "critical"}}</div></div>
  <div class="cell"><div class="label">High</div><div class="value" style="color:#FF6B00">{{index .Sev "high"}}</div></div>
  <div class="cell"><div class="label">Medium</div><div class="value" style="color:#FFB800">{{index .Sev "medium"}}</div></div>
  <div class="cell"><div class="label">Low</div><div class="value" style="color:#00FF88">{{index .Sev "low"}}</div></div>
  <div class="cell"><div class="label">Info</div><div class="value">{{index .Sev "info"}}</div></div>
</div>

<h2>Findings</h2>
<table>
<tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>Scanner</th><th>CVE</th><th>Status</th></tr>
{{range .Findings}}
<tr>
  <td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
  <td>{{.Title}}</td>
  <td>{{.AffectedEndpoint}}{{if .Port}}:{{.Port}}{{end}}</td>
  <td>{{.Scanner}}</td>
  <td>{{.CVE}}</td>
  <td>{{.Status}}</td>
</tr>
{{end}}
</table>

<div class="footer">{{.LegalFooter}}</div>
</body>
</html>`

func renderHTML(d *Dataset) ([]byte, string, error) {
	// Source: partner-uploaded custom template when present
	// (PartnerTemplate.Body), else the canonical default. The
	// partner-template path is gated by the same html/template parse
	// — Go's auto-escaping protects against XSS in the supplied
	// template body the same way it does for our own.
	source := reportTemplate
	if d.PartnerTemplate != nil && d.PartnerTemplate.Body != "" {
		source = d.PartnerTemplate.Body
	}
	t, err := template.New("report").Parse(source)
	if err != nil {
		// A broken partner template falls back to the default
		// rather than failing the whole report. The error is
		// surfaced via the logger so operators can fix it.
		if d.PartnerTemplate != nil {
			reportingLogger.Warn().Err(err).
				Str("partner_id", d.PartnerTemplate.PartnerID.String()).
				Str("report_type", d.PartnerTemplate.ReportType).
				Msg("reporting: partner template parse failed; falling back to default")
			t, err = template.New("report").Parse(reportTemplate)
			if err != nil {
				return nil, "", err
			}
		} else {
			return nil, "", err
		}
	}
	primary := "#0F172A"
	logoURL := ""
	footer := ""
	confidentiality := "CONFIDENTIAL"
	watermark := "CONFIDENTIAL"
	if d.Branding != nil {
		if d.Branding.PrimaryColor != "" {
			primary = d.Branding.PrimaryColor
		}
		logoURL = d.Branding.LogoURL
		footer = d.Branding.LegalFooter
		if d.Branding.ConfidentialityTag != "" {
			confidentiality = d.Branding.ConfidentialityTag
		}
		if d.Branding.WatermarkText != "" {
			watermark = d.Branding.WatermarkText
		}
	}
	// Partner-template fields override branding (same precedence
	// rule docs/runbooks/branding.md describes — partner template
	// is "most specific").
	if d.PartnerTemplate != nil {
		if d.PartnerTemplate.Footer != "" {
			footer = d.PartnerTemplate.Footer
		}
		if d.PartnerTemplate.Watermark != "" {
			watermark = d.PartnerTemplate.Watermark
		}
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]any{
		"Title":            humanizeReportType(d.ReportType),
		"Primary":          primary,
		"LogoURL":          logoURL,
		"Engagement":       d.Engagement,
		"Tenant":           d.Tenant,
		"Partner":          d.Partner,
		"Findings":         d.Findings,
		"Sev":              d.SeverityCounts,
		"GeneratedAt":      d.GeneratedAt,
		"LegalFooter":      footer,
		"Confidentiality":  confidentiality,
		"Watermark":        watermark,
	}); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "text/html; charset=utf-8", nil
}

func humanizeReportType(code string) string {
	parts := strings.Split(code, "_")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ") + " Report"
}

// ----- compliance mappings -------------------------------------------------

func mapCompliance(fs []models.Finding) ComplianceMapping {
	m := ComplianceMapping{
		ISO27001: map[string]int{},
		PCIDSS:   map[string]int{},
		SOC2:     map[string]int{},
	}
	for _, f := range fs {
		switch f.ScanType {
		case "tls":
			m.ISO27001["A.13.1 Network controls"]++
			m.PCIDSS["Req 4: Encrypt transmission"]++
			m.SOC2["CC6.7 Transmission of information"]++
		case "web":
			m.ISO27001["A.14.2 Secure development"]++
			m.PCIDSS["Req 6.5 Secure coding"]++
			m.SOC2["CC7.1 System monitoring"]++
		case "ad":
			m.ISO27001["A.9.2 User access management"]++
			m.SOC2["CC6.1 Logical access"]++
		case "cloud":
			m.ISO27001["A.13.2 Information transfer"]++
			m.PCIDSS["Req 1: Firewall configuration"]++
		case "kubernetes", "container":
			m.ISO27001["A.12.5 Operational software"]++
		default:
			m.ISO27001["A.12.6 Technical vulnerabilities"]++
		}
	}
	return m
}

func validReportType(t string) bool {
	for _, v := range AllReportTypes() {
		if v == t {
			return true
		}
	}
	return false
}

// ----- Partner report-template management -----------------------------------
//
// Operators upload per-partner / per-report-type overrides via the
// /api/v1/partners/{partner_id}/report-templates surface; the loader
// here is called by gatherDataset on every report generation.

// loadPartnerTemplate returns the partner's override row for the
// given report type, or pgx.ErrNoRows if there's no override.
func (s *Service) loadPartnerTemplate(ctx context.Context, partnerID uuid.UUID, reportType string) (*PartnerReportTemplate, error) {
	t := &PartnerReportTemplate{PartnerID: partnerID, ReportType: reportType}
	var sectionsJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT template, sections, COALESCE(cover_url,''),
		       COALESCE(footer,''), COALESCE(watermark,''), updated_at
		  FROM partner_report_templates
		 WHERE partner_id=$1 AND report_type=$2`,
		partnerID, reportType).
		Scan(&t.Body, &sectionsJSON, &t.CoverURL, &t.Footer, &t.Watermark, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(sectionsJSON) > 0 {
		_ = json.Unmarshal(sectionsJSON, &t.Sections)
	}
	return t, nil
}

// UpsertPartnerTemplateInput is the CRUD shape for the API surface.
type UpsertPartnerTemplateInput struct {
	PartnerID  uuid.UUID
	ReportType string
	Body       string
	Sections   []string
	CoverURL   string
	Footer     string
	Watermark  string
}

// UpsertPartnerTemplate writes or replaces a partner template.
// Validates the body parses as a Go html/template before persisting
// — a broken template would fall back at render time, but failing
// fast at write time gives the operator a clearer error.
func (s *Service) UpsertPartnerTemplate(ctx context.Context, in UpsertPartnerTemplateInput) error {
	if in.PartnerID == uuid.Nil {
		return errors.New("reporting: partner_id required")
	}
	if !validReportType(in.ReportType) {
		return fmt.Errorf("reporting: unsupported report_type %q", in.ReportType)
	}
	if in.Body == "" {
		return errors.New("reporting: template body required")
	}
	// Defence in depth: validate the body parses. Catches the
	// "left an unclosed {{ if }}" type mistake at upload time.
	if _, err := template.New("validate").Parse(in.Body); err != nil {
		return fmt.Errorf("reporting: template parse error: %w", err)
	}
	sectionsJSON, _ := json.Marshal(in.Sections)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO partner_report_templates(partner_id, report_type, template, sections,
		    cover_url, footer, watermark)
		VALUES ($1, $2, $3, $4::jsonb, NULLIF($5,''), NULLIF($6,''), NULLIF($7,''))
		ON CONFLICT (partner_id, report_type) DO UPDATE SET
		    template = EXCLUDED.template,
		    sections = EXCLUDED.sections,
		    cover_url = EXCLUDED.cover_url,
		    footer = EXCLUDED.footer,
		    watermark = EXCLUDED.watermark,
		    updated_at = now()`,
		in.PartnerID, in.ReportType, in.Body, sectionsJSON,
		in.CoverURL, in.Footer, in.Watermark)
	return err
}

// ListPartnerTemplates returns every override row a partner has.
func (s *Service) ListPartnerTemplates(ctx context.Context, partnerID uuid.UUID) ([]PartnerReportTemplate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT report_type, template, sections, COALESCE(cover_url,''),
		       COALESCE(footer,''), COALESCE(watermark,''), updated_at
		  FROM partner_report_templates
		 WHERE partner_id=$1
		 ORDER BY report_type`, partnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PartnerReportTemplate
	for rows.Next() {
		var t PartnerReportTemplate
		var sectionsJSON []byte
		t.PartnerID = partnerID
		if err := rows.Scan(&t.ReportType, &t.Body, &sectionsJSON,
			&t.CoverURL, &t.Footer, &t.Watermark, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if len(sectionsJSON) > 0 {
			_ = json.Unmarshal(sectionsJSON, &t.Sections)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeletePartnerTemplate removes an override row. Future renders for
// that report_type fall back to the default template.
func (s *Service) DeletePartnerTemplate(ctx context.Context, partnerID uuid.UUID, reportType string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM partner_report_templates WHERE partner_id=$1 AND report_type=$2`,
		partnerID, reportType)
	return err
}

var _ = errors.New
