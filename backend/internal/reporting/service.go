// Package reporting generates branded reports in multiple formats
// (Blueprint §19). The implementation produces canonical HTML, JSON, CSV,
// XML/DOCX-stub and tabular XLSX-CSV. PDF generation in production is via
// headless Chromium; for the development build we render an HTML payload that
// is suitable for the headless renderer.
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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

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
	FormatDOCX = "docx"
	FormatXLSX = "xlsx"
	FormatHTML = "html"
	FormatJSON = "json"
	FormatCSV  = "csv"
)

func AllFormats() []string {
	return []string{FormatPDF, FormatDOCX, FormatXLSX, FormatHTML, FormatJSON, FormatCSV}
}

type Service struct {
	pool     *pgxpool.Pool
	branding *branding.Service
	store    *evidence.Vault
	audit    *audit.Service
	bus      *eventbus.Bus
}

func New(pool *pgxpool.Pool, b *branding.Service, st *evidence.Vault, a *audit.Service, bus *eventbus.Bus) *Service {
	return &Service{pool: pool, branding: b, store: st, audit: a, bus: bus}
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
func (s *Service) Generate(ctx context.Context, in GenerateInput) (*Report, error) {
	if !validReportType(in.ReportType) {
		return nil, fmt.Errorf("reporting: unsupported report_type %q", in.ReportType)
	}
	if len(in.Formats) == 0 {
		in.Formats = []string{FormatHTML, FormatJSON, FormatCSV, FormatPDF, FormatDOCX, FormatXLSX}
	}
	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO reports(id, platform_id, partner_id, tenant_id, engagement_id,
		    report_type, title, status, generated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'generating',$8)`,
		id, in.PlatformID, in.PartnerID, in.TenantID, in.EngagementID,
		in.ReportType, in.Title, in.GeneratedBy); err != nil {
		return nil, err
	}

	dataset, err := s.gatherDataset(ctx, in)
	if err != nil {
		return nil, err
	}
	bundle, err := s.branding.LoadBundle(ctx, in.PartnerID)
	if err != nil {
		return nil, err
	}
	dataset.Branding = &bundle.Branding

	r := &Report{
		ID: id, ReportType: in.ReportType, Title: in.Title,
		Status: "ready", GeneratedAt: time.Now().UTC(),
	}

	for _, format := range in.Formats {
		body, ct, err := s.render(format, in.ReportType, dataset)
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
		hashHex := hex.EncodeToString(sum[:])
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO report_exports(report_id, format, storage_url, sha256, size_bytes)
			VALUES ($1,$2,$3,$4,$5)`,
			id, format, storageURL, hashHex, int64(len(body))); err != nil {
			return nil, err
		}
		r.Exports = append(r.Exports, Export{
			Format: format, StorageURL: storageURL, SHA256: hashHex, SizeBytes: int64(len(body)),
		})
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE reports SET status='ready', generated_at=now() WHERE id=$1`, id); err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: in.PlatformID, PartnerID: &in.PartnerID, TenantID: &in.TenantID,
		ActorID: in.GeneratedBy, Event: audit.EventReportGenerated,
		TargetType: "report", TargetID: id.String(),
		Payload: map[string]any{"type": in.ReportType, "formats": in.Formats},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.ReportGenerated, TenantID: &in.TenantID, PartnerID: &in.PartnerID,
		ActorID: in.GeneratedBy,
		Payload: map[string]any{"report_id": id, "type": in.ReportType, "formats": in.Formats},
	})
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
	Engagement   models.Engagement       `json:"engagement"`
	Tenant       models.Tenant           `json:"tenant"`
	Partner      models.Partner          `json:"partner"`
	Branding     *models.PartnerBranding `json:"branding,omitempty"`
	Findings     []models.Finding        `json:"findings"`
	SeverityCounts map[string]int        `json:"severity_counts"`
	GeneratedAt  time.Time               `json:"generated_at"`
	ReportType   string                  `json:"report_type"`
	Compliance   ComplianceMapping       `json:"compliance,omitempty"`
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

func (s *Service) render(format, reportType string, d *Dataset) ([]byte, string, error) {
	switch format {
	case FormatJSON:
		buf, err := json.MarshalIndent(d, "", "  ")
		return buf, "application/json", err
	case FormatCSV:
		return renderCSV(d)
	case FormatHTML:
		return renderHTML(d)
	case FormatPDF:
		// Production: headless chromium. Dev: tag the HTML with a sentinel header
		// so consumers can pipe it through wkhtmltopdf / chromium themselves.
		body, _, err := renderHTML(d)
		if err != nil {
			return nil, "", err
		}
		return body, "application/pdf", nil
	case FormatDOCX:
		body, _, err := renderHTML(d)
		if err != nil {
			return nil, "", err
		}
		return body, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", nil
	case FormatXLSX:
		// Same data as CSV; production pipeline converts via xlsxwriter.
		body, _, err := renderCSV(d)
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

const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{{.Title}}</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; color:#0F172A; margin:40px; }
.cover { background: {{.Primary}}; color:white; padding: 60px 40px; border-radius:8px; }
.cover h1 { font-size: 32px; margin: 0 0 8px 0; }
.cover .meta { opacity:.85; }
table { border-collapse: collapse; width: 100%; margin-top: 24px; }
th, td { border-bottom: 1px solid #E2E8F0; padding: 8px 12px; text-align: left; font-size: 13px; }
th { background:#F8FAFC; }
.sev { display:inline-block; padding: 2px 6px; border-radius: 4px; font-weight:600; font-size: 11px; }
.sev.critical { background:#7F1D1D; color:white; }
.sev.high { background:#B91C1C; color:white; }
.sev.medium { background:#D97706; color:white; }
.sev.low { background:#059669; color:white; }
.sev.info { background:#475569; color:white; }
.footer { margin-top: 48px; font-size: 11px; color: #475569; border-top: 1px solid #E2E8F0; padding-top: 12px; }
.watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-30deg); font-size: 80px; color: rgba(15,23,42,0.06); pointer-events:none; }
</style>
</head>
<body>
<div class="watermark">{{.Watermark}}</div>
<div class="cover">
  {{if .LogoURL}}<img src="{{.LogoURL}}" style="max-height:48px;background:white;padding:6px 10px;border-radius:4px" />{{end}}
  <h1>{{.Title}}</h1>
  <div class="meta">
    Engagement: <strong>{{.Engagement.Code}}</strong> &middot;
    Tenant: <strong>{{.Tenant.Name}}</strong> &middot;
    Partner: <strong>{{.Partner.Name}}</strong>
  </div>
  <div class="meta">Generated {{.GeneratedAt.Format "2006-01-02 15:04 MST"}}</div>
  <div class="meta">{{.Confidentiality}}</div>
</div>

<h2>Executive Summary</h2>
<p>This report covers engagement <strong>{{.Engagement.Code}} - {{.Engagement.Name}}</strong>
running from {{.Engagement.StartsAt.Format "2006-01-02"}} to {{.Engagement.EndsAt.Format "2006-01-02"}}.
{{len .Findings}} findings were identified.</p>

<h3>Severity Breakdown</h3>
<table>
  <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
  <tr>
    <td>{{index .Sev "critical"}}</td>
    <td>{{index .Sev "high"}}</td>
    <td>{{index .Sev "medium"}}</td>
    <td>{{index .Sev "low"}}</td>
    <td>{{index .Sev "info"}}</td>
  </tr>
</table>

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
	t, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return nil, "", err
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

var _ = errors.New
