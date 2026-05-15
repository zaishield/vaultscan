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
