package reporting

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

func writeTempFile(pattern string, body []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if len(body) > 0 {
		if _, err := f.Write(body); err != nil {
			os.Remove(f.Name())
			return "", err
		}
	}
	return f.Name(), nil
}

func removeTempFile(p string) { _ = os.Remove(p) }
func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

// ----- PDF rendering --------------------------------------------------------

// PDFRenderer turns canonical report HTML into PDF bytes. Two impls:
//   1. ChromiumRenderer — shells out to `chromium-browser --headless`
//      (or `google-chrome`, `chromium`, `chrome`) to produce a real PDF.
//   2. htmlFallbackRenderer — embeds the HTML behind a 4-byte sentinel
//      so downstream pipelines (or operators) can tell the output is
//      not a real PDF and convert it themselves.
//
// The active renderer is auto-detected at boot: ChromiumRenderer if a
// chromium-compatible binary is on PATH, fallback otherwise.
type PDFRenderer interface {
	Name() string
	Render(ctx context.Context, html []byte) ([]byte, error)
}

func DetectPDFRenderer() PDFRenderer {
	for _, candidate := range []string{"chromium-browser", "chromium", "google-chrome", "chrome"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return &ChromiumRenderer{binary: path}
		}
	}
	return &htmlFallbackRenderer{}
}

type ChromiumRenderer struct {
	binary string
}

func (c *ChromiumRenderer) Name() string { return "chromium" }

// Render writes the HTML to a temp file, calls headless chromium to
// produce a PDF to another temp file, reads it, returns the bytes.
// Timeout: 60s.
func (c *ChromiumRenderer) Render(ctx context.Context, html []byte) ([]byte, error) {
	in, err := writeTempFile("vaultscan-report-*.html", html)
	if err != nil {
		return nil, err
	}
	defer removeTempFile(in)
	out, err := writeTempFile("vaultscan-report-*.pdf", nil)
	if err != nil {
		return nil, err
	}
	defer removeTempFile(out)

	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, c.binary,
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--print-to-pdf="+out,
		"--print-to-pdf-no-header",
		"file://"+in,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("reporting: chromium PDF failed: %w (stderr: %s)", err, stderr.String())
	}
	body, err := readFile(out)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		return nil, errors.New("reporting: chromium produced non-PDF output")
	}
	return body, nil
}

type htmlFallbackRenderer struct{}

func (htmlFallbackRenderer) Name() string { return "html-fallback" }

// Render prepends a sentinel header so reviewers can spot the placeholder.
func (htmlFallbackRenderer) Render(_ context.Context, html []byte) ([]byte, error) {
	prefix := []byte("<!-- VAULTSCAN-PDF-FALLBACK chromium not detected; pipe through wkhtmltopdf -->\n")
	return append(prefix, html...), nil
}

// AttachPDFRenderer lets callers swap the active renderer (tests, etc.).
// When set, Generate uses this renderer; otherwise the legacy "html bytes
// labelled as pdf" path stays put.
func (s *Service) AttachPDFRenderer(r PDFRenderer) { s.pdfRenderer = r }

// ----- Compliance mapping ---------------------------------------------------

type Control struct {
	ID               uuid.UUID `json:"id"`
	Framework        string    `json:"framework"`
	FrameworkVersion string    `json:"framework_version"`
	ControlCode      string    `json:"control_code"`
	Title            string    `json:"title"`
	Description      string    `json:"description,omitempty"`
	Patterns         []string  `json:"finding_patterns,omitempty"`
}

func (s *Service) ListControls(ctx context.Context, framework string) ([]Control, error) {
	q := `SELECT id, framework, framework_version, control_code, title,
	             COALESCE(description,''), COALESCE(finding_patterns::text, '[]')
	        FROM compliance_controls`
	args := []any{}
	if framework != "" {
		q += " WHERE framework=$1"
		args = append(args, framework)
	}
	q += " ORDER BY framework, control_code"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Control
	for rows.Next() {
		var c Control
		var patsRaw string
		if err := rows.Scan(&c.ID, &c.Framework, &c.FrameworkVersion, &c.ControlCode,
			&c.Title, &c.Description, &patsRaw); err != nil {
			return nil, err
		}
		// Tolerant unmarshal: patterns is a JSON array of strings.
		c.Patterns = parsePatterns(patsRaw)
		out = append(out, c)
	}
	return out, rows.Err()
}

func parsePatterns(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" || raw == "null" {
		return nil
	}
	// Minimal parse: trim brackets + split on commas + unquote.
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ControlCoverage holds per-control match counts for an engagement.
type ControlCoverage struct {
	Control     Control `json:"control"`
	Matches     int     `json:"finding_matches"`
	SeverityMix map[string]int `json:"severity_mix,omitempty"`
}

// ComplianceMatrix evaluates every control in the named framework against
// the engagement's findings, returning per-control match counts and a
// per-severity breakdown. Used by the compliance report template.
func (s *Service) ComplianceMatrix(ctx context.Context, framework string, engagementID uuid.UUID) ([]ControlCoverage, error) {
	controls, err := s.ListControls(ctx, framework)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT lower(title), severity FROM findings
		 WHERE engagement_id=$1`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type f struct{ title, sev string }
	var fs []f
	for rows.Next() {
		var x f
		if err := rows.Scan(&x.title, &x.sev); err != nil {
			return nil, err
		}
		fs = append(fs, x)
	}

	out := make([]ControlCoverage, 0, len(controls))
	for _, c := range controls {
		cov := ControlCoverage{Control: c, SeverityMix: map[string]int{}}
		for _, p := range c.Patterns {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				continue
			}
			for _, x := range fs {
				if re.MatchString(x.title) {
					cov.Matches++
					cov.SeverityMix[x.sev]++
				}
			}
		}
		out = append(out, cov)
	}
	return out, nil
}

// ComplianceMarkdown renders a coverage table for inclusion in a report.
func (s *Service) ComplianceMarkdown(ctx context.Context, framework string, engagementID uuid.UUID) (string, error) {
	matrix, err := s.ComplianceMatrix(ctx, framework, engagementID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Compliance Coverage — %s\n\n", strings.ToUpper(framework))
	fmt.Fprintf(&b, "| Control | Title | Findings | Critical | High | Medium | Low |\n")
	fmt.Fprintf(&b, "|---------|-------|---------:|---------:|-----:|-------:|----:|\n")
	for _, c := range matrix {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %d |\n",
			c.Control.ControlCode, c.Control.Title, c.Matches,
			c.SeverityMix["critical"], c.SeverityMix["high"],
			c.SeverityMix["medium"], c.SeverityMix["low"])
	}
	return b.String(), nil
}

// ----- Scheduled report runs ------------------------------------------------

type Schedule struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	EngagementID  *uuid.UUID `json:"engagement_id,omitempty"`
	Name          string     `json:"name"`
	ReportType    string     `json:"report_type"`
	Cadence       string     `json:"cadence"`
	Enabled       bool       `json:"enabled"`
	NextRunAt     time.Time  `json:"next_run_at"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastReportID  *uuid.UUID `json:"last_report_id,omitempty"`
}

type CreateScheduleInput struct {
	PlatformID   uuid.UUID
	PartnerID    uuid.UUID
	TenantID     uuid.UUID
	EngagementID *uuid.UUID
	Name         string
	ReportType   string
	Cadence      string
	Formats      []string
	FirstRunAt   time.Time
	CreatedBy    *uuid.UUID
}

func (s *Service) CreateSchedule(ctx context.Context, in CreateScheduleInput) (uuid.UUID, error) {
	if !validReportType(in.ReportType) {
		return uuid.Nil, fmt.Errorf("reporting: unknown report_type %q", in.ReportType)
	}
	if !validCadence(in.Cadence) {
		return uuid.Nil, fmt.Errorf("reporting: invalid cadence %q", in.Cadence)
	}
	if in.FirstRunAt.IsZero() {
		in.FirstRunAt = time.Now().UTC().Add(time.Minute)
	}
	if len(in.Formats) == 0 {
		in.Formats = []string{FormatPDF, FormatHTML, FormatJSON}
	}
	formats := `["` + strings.Join(in.Formats, `","`) + `"]`
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO report_schedules(platform_id, partner_id, tenant_id, engagement_id,
		    name, report_type, formats, cadence, next_run_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)
		RETURNING id`,
		in.PlatformID, in.PartnerID, in.TenantID, in.EngagementID,
		in.Name, in.ReportType, formats, in.Cadence, in.FirstRunAt, in.CreatedBy).
		Scan(&id)
	return id, err
}

func validCadence(c string) bool {
	switch c {
	case "daily", "weekly", "monthly", "quarterly":
		return true
	}
	return false
}

// DueSchedules returns enabled schedules whose next_run_at <= now.
func (s *Service) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, engagement_id, name, report_type, cadence,
		       enabled, next_run_at, last_run_at, last_report_id
		  FROM report_schedules
		 WHERE enabled = true AND next_run_at <= $1
		 ORDER BY next_run_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		var s Schedule
		if err := rows.Scan(&s.ID, &s.TenantID, &s.EngagementID, &s.Name,
			&s.ReportType, &s.Cadence, &s.Enabled, &s.NextRunAt,
			&s.LastRunAt, &s.LastReportID); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AdvanceSchedule bumps next_run_at by the cadence. last_report_id ties
// the row to the generated report.
func (s *Service) AdvanceSchedule(ctx context.Context, scheduleID, reportID uuid.UUID, now time.Time) error {
	var cadence string
	if err := s.pool.QueryRow(ctx,
		`SELECT cadence FROM report_schedules WHERE id=$1`, scheduleID).Scan(&cadence); err != nil {
		return err
	}
	next := cadenceNext(now, cadence)
	_, err := s.pool.Exec(ctx, `
		UPDATE report_schedules
		   SET next_run_at = $2,
		       last_run_at = $3,
		       last_report_id = $4
		 WHERE id = $1`, scheduleID, next, now, reportID)
	return err
}

func cadenceNext(from time.Time, cadence string) time.Time {
	switch cadence {
	case "daily":
		return from.Add(24 * time.Hour)
	case "weekly":
		return from.Add(7 * 24 * time.Hour)
	case "monthly":
		return from.AddDate(0, 1, 0)
	case "quarterly":
		return from.AddDate(0, 3, 0)
	}
	return from.Add(24 * time.Hour)
}

// RunDue is the scheduler tick: pick every due schedule, fire the Generate
// path, advance next_run_at. Designed for periodic cron-style invocation.
// Returns the schedule IDs that were run.
func (s *Service) RunDue(ctx context.Context) ([]uuid.UUID, error) {
	now := time.Now().UTC()
	due, err := s.DueSchedules(ctx, now)
	if err != nil {
		return nil, err
	}
	var ran []uuid.UUID
	for _, sched := range due {
		eng := uuid.Nil
		if sched.EngagementID != nil {
			eng = *sched.EngagementID
		}
		// Re-fetch the platform/partner/title from the row — DueSchedules
		// keeps the projection small.
		var (
			platformID, partnerID, tenantID uuid.UUID
			engID                            *uuid.UUID
			rType, name                      string
		)
		_ = s.pool.QueryRow(ctx, `
			SELECT platform_id, partner_id, tenant_id, engagement_id, report_type, name
			  FROM report_schedules WHERE id=$1`, sched.ID).
			Scan(&platformID, &partnerID, &tenantID, &engID, &rType, &name)
		if engID != nil {
			eng = *engID
		}
		r, err := s.Generate(ctx, GenerateInput{
			PlatformID: platformID, PartnerID: partnerID,
			TenantID: tenantID, EngagementID: eng,
			ReportType: rType, Title: fmt.Sprintf("%s (scheduled %s)", name, now.Format("2006-01-02")),
			Formats:    []string{FormatHTML, FormatJSON, FormatPDF},
		})
		if err != nil {
			continue
		}
		_ = s.AdvanceSchedule(ctx, sched.ID, r.ID, now)
		ran = append(ran, sched.ID)
	}
	sort.Slice(ran, func(i, j int) bool { return ran[i].String() < ran[j].String() })
	return ran, nil
}
