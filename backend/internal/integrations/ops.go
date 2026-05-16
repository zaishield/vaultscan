package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// ---------------- Jira ------------------------------------------------------

// BuildJiraIssue produces a Jira REST v3 issue body suitable for POST to
// /rest/api/3/issue. Inputs come from the integration's config:
//   project_key  → ZAI
//   issue_type   → Bug | Task | Vulnerability   (defaults to issuetype config or Bug)
// Custom fields (CVE, CVSS, severity) go under fields so customers can
// map them in their Jira project.
func BuildJiraIssue(ev eventbus.Event, config map[string]any, issueType string) ([]byte, error) {
	projectKey, _ := config["project_key"].(string)
	if projectKey == "" {
		return nil, errors.New("integrations/jira: project_key required in config")
	}
	if issueType == "" {
		if v, ok := config["issue_type"].(string); ok && v != "" {
			issueType = v
		} else {
			issueType = "Bug"
		}
	}
	payload := ev.Payload
	severity, _ := stringFromPayload(payload, "severity")
	cve, _ := stringFromPayload(payload, "cve")
	cvss := numberFromPayload(payload, "cvss_score")
	title, _ := stringFromPayload(payload, "title")
	if title == "" {
		title = fmt.Sprintf("[VAULTSCAN] %s — %s", ev.Type, ev.ID)
	}
	body := map[string]any{
		"fields": map[string]any{
			"project":   map[string]any{"key": projectKey},
			"summary":   title,
			"issuetype": map[string]any{"name": issueType},
			"priority":  map[string]any{"name": jiraPriority(severity)},
			"labels":    []string{"vaultscan", "severity-" + severity},
			"description": map[string]any{
				"type":    "doc",
				"version": 1,
				"content": []map[string]any{
					{
						"type": "paragraph",
						"content": []map[string]any{
							{"type": "text", "text": fmt.Sprintf(
								"Event %s (event_id=%s).\nCVE: %s\nCVSS: %.1f",
								ev.Type, ev.ID, cve, cvss)},
						},
					},
				},
			},
		},
	}
	// Custom field mapping. config["custom_fields"] is "cf_cve":"customfield_10001" etc.
	if cf, ok := config["custom_fields"].(map[string]any); ok {
		fields := body["fields"].(map[string]any)
		if k, ok := cf["cve"].(string); ok && k != "" {
			fields[k] = cve
		}
		if k, ok := cf["cvss"].(string); ok && k != "" {
			fields[k] = cvss
		}
		if k, ok := cf["severity"].(string); ok && k != "" {
			fields[k] = severity
		}
	}
	return json.Marshal(body)
}

func jiraPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return "Lowest"
}

// ---------------- ServiceNow ------------------------------------------------

// BuildServiceNowIncident produces the body for POST /api/now/table/incident.
// Maps severity → urgency: critical=1, high=2, medium=3, low/info=4.
func BuildServiceNowIncident(ev eventbus.Event, config map[string]any) ([]byte, error) {
	payload := ev.Payload
	severity, _ := stringFromPayload(payload, "severity")
	title, _ := stringFromPayload(payload, "title")
	if title == "" {
		title = fmt.Sprintf("VAULTSCAN: %s", ev.Type)
	}
	cve, _ := stringFromPayload(payload, "cve")
	urgency := snowUrgency(severity)
	caller, _ := config["caller_id"].(string)
	body := map[string]any{
		"short_description": title,
		"description":       fmt.Sprintf("Event %s emitted by VAULTSCAN.\nCVE: %s", ev.Type, cve),
		"category":          "Security",
		"subcategory":       "Vulnerability",
		"urgency":           urgency,
		"impact":            urgency,
		"u_vaultscan_event": ev.Type,
		"u_vaultscan_event_id": ev.ID,
	}
	if caller != "" {
		body["caller_id"] = caller
	}
	return json.Marshal(body)
}

func snowUrgency(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	}
	return 4
}

// ---------------- CEF / LEEF ------------------------------------------------

// BuildCEF returns an ArcSight CEF 0 line:
//   CEF:0|ZAISHIELD|VAULTSCAN|1.0|<eventType>|<title>|<severity>|<extensions>
// Extensions are CEF key=value pairs separated by spaces; reserved
// chars in values are escaped (\\, \= and \|).
func BuildCEF(ev eventbus.Event) string {
	severity := numericSeverityCEF(stringValOr(ev.Payload, "severity", "info"))
	title := stringValOr(ev.Payload, "title", string(ev.Type))
	exts := map[string]string{
		"externalId": ev.ID.String(),
		"act":        string(ev.Type),
		"rt":         fmt.Sprintf("%d", time.Now().UTC().UnixMilli()),
	}
	if ev.TenantID != nil {
		exts["cs1Label"] = "tenant_id"
		exts["cs1"] = ev.TenantID.String()
	}
	if cve, _ := stringFromPayload(ev.Payload, "cve"); cve != "" {
		exts["cs2Label"] = "cve"
		exts["cs2"] = cve
	}
	if cvss := numberFromPayload(ev.Payload, "cvss_score"); cvss > 0 {
		exts["cn1Label"] = "cvss_score"
		exts["cn1"] = fmt.Sprintf("%.1f", cvss)
	}
	return fmt.Sprintf("CEF:0|ZAISHIELD|VAULTSCAN|1.0|%s|%s|%d|%s",
		cefEscapeHeader(string(ev.Type)),
		cefEscapeHeader(title), severity, formatCEFExtensions(exts))
}

// BuildLEEF returns a LEEF 2.0 line:
//   LEEF:2.0|ZAISHIELD|VAULTSCAN|1.0|<eventType>|^|key=value^key=value
func BuildLEEF(ev eventbus.Event) string {
	severity := stringValOr(ev.Payload, "severity", "info")
	exts := map[string]string{
		"event_id":   ev.ID.String(),
		"severity":   severity,
		"tenant_id":  uuidStrOrEmpty(ev.TenantID),
		"event_type": string(ev.Type),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	if cve, _ := stringFromPayload(ev.Payload, "cve"); cve != "" {
		exts["cve"] = cve
	}
	if title, _ := stringFromPayload(ev.Payload, "title"); title != "" {
		exts["title"] = title
	}
	return fmt.Sprintf("LEEF:2.0|ZAISHIELD|VAULTSCAN|1.0|%s|^|%s",
		string(ev.Type), formatLEEFExtensions(exts))
}

func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	// Strip line terminators — CEF is single-line over syslog; an
	// attacker-controlled newline would inject a forged event into
	// the SIEM ingest pipeline.
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

func cefEscapeValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

func formatCEFExtensions(exts map[string]string) string {
	keys := make([]string, 0, len(exts))
	for k := range exts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := cefEscapeValue(exts[k])
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, " ")
}

func formatLEEFExtensions(exts map[string]string) string {
	keys := make([]string, 0, len(exts))
	for k := range exts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		// LEEF delimiter is ^ (specified in the header). Replace ^ in
		// values with a Unicode escape so the parser doesn't break.
		// Also strip line terminators — LEEF is single-line over
		// syslog and a smuggled newline would inject a forged event.
		v := exts[k]
		v = strings.ReplaceAll(v, "^", "\\u005e")
		v = strings.ReplaceAll(v, "\n", "\\n")
		v = strings.ReplaceAll(v, "\r", "\\r")
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, "^")
}

func numericSeverityCEF(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	}
	return 1
}

// ---------------- Dead-letter queue -----------------------------------------

type DeadLetter struct {
	ID             uuid.UUID `json:"id"`
	IntegrationID  uuid.UUID `json:"integration_id"`
	EventID        uuid.UUID `json:"event_id"`
	EventType      string    `json:"event_type"`
	Attempts       int       `json:"attempts"`
	LastError      string    `json:"last_error,omitempty"`
	LastStatusCode int       `json:"last_status_code,omitempty"`
	Payload        []byte    `json:"-"`
	EnqueuedAt     time.Time `json:"enqueued_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	Resolution     string    `json:"resolution,omitempty"`
}

// EnqueueDeadLetter is invoked when delivery exhausts retries.
func (s *Service) EnqueueDeadLetter(ctx context.Context, integrationID uuid.UUID, ev eventbus.Event, attempts int, lastError string, lastCode int) (uuid.UUID, error) {
	payload, _ := json.Marshal(ev)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO integration_dead_letters(integration_id, event_id, event_type,
		    payload, attempts, last_error, last_status_code)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
		RETURNING id`,
		integrationID, ev.ID, ev.Type, payload, attempts, lastError, nullIfZero(lastCode)).
		Scan(&id)
	return id, err
}

func (s *Service) ListDeadLetters(ctx context.Context, integrationID uuid.UUID) ([]DeadLetter, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, integration_id, event_id, event_type, attempts,
		       COALESCE(last_error,''), COALESCE(last_status_code, 0),
		       payload, enqueued_at, resolved_at, COALESCE(resolution,'')
		  FROM integration_dead_letters
		 WHERE integration_id=$1
		 ORDER BY enqueued_at DESC`, integrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeadLetter
	for rows.Next() {
		var d DeadLetter
		if err := rows.Scan(&d.ID, &d.IntegrationID, &d.EventID, &d.EventType,
			&d.Attempts, &d.LastError, &d.LastStatusCode, &d.Payload,
			&d.EnqueuedAt, &d.ResolvedAt, &d.Resolution); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkDeadLetterResolved transitions a DLQ entry to resolved with the
// given resolution ("replayed" | "dropped" | "quarantined").
func (s *Service) MarkDeadLetterResolved(ctx context.Context, id uuid.UUID, resolution string) error {
	if resolution != "replayed" && resolution != "dropped" && resolution != "quarantined" {
		return fmt.Errorf("integrations: bad resolution %q", resolution)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE integration_dead_letters
		   SET resolved_at = now(), resolution = $2
		 WHERE id = $1 AND resolved_at IS NULL`, id, resolution)
	return err
}

// Replay pulls a DLQ entry's stored event payload, fires it through the
// integration's deliver path, records the outcome in integration_replays,
// and (on success) marks the DLQ entry resolved.
func (s *Service) Replay(ctx context.Context, dlqID uuid.UUID, actor *uuid.UUID) error {
	var (
		integrationID uuid.UUID
		eventJSON     []byte
	)
	if err := s.pool.QueryRow(ctx,
		`SELECT integration_id, payload FROM integration_dead_letters
		  WHERE id=$1 AND resolved_at IS NULL`, dlqID).
		Scan(&integrationID, &eventJSON); err != nil {
		return err
	}
	var ev eventbus.Event
	if err := json.Unmarshal(eventJSON, &ev); err != nil {
		return fmt.Errorf("integrations: decode payload: %w", err)
	}
	// Re-trigger fanout for this single integration.
	var (
		itype, name, secretRef string
		configRaw              []byte
	)
	if err := s.pool.QueryRow(ctx,
		`SELECT type, name, COALESCE(secret_ref,''), config
		   FROM integrations WHERE id=$1`, integrationID).
		Scan(&itype, &name, &secretRef, &configRaw); err != nil {
		return err
	}
	var config map[string]any
	_ = json.Unmarshal(configRaw, &config)

	var replayID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO integration_replays(dead_letter_id, requested_by, outcome)
		VALUES ($1, $2, 'pending') RETURNING id`, dlqID, actor).Scan(&replayID); err != nil {
		return err
	}
	s.deliver(ctx, integrationID, itype, name, config, ev)
	// Inspect the most recent delivery row to fill in the outcome.
	var status string
	var code *int
	var resp string
	_ = s.pool.QueryRow(ctx, `
		SELECT status, response_code, COALESCE(response_body,'')
		  FROM integration_deliveries
		 WHERE integration_id=$1 AND event_id=$2
		 ORDER BY created_at DESC LIMIT 1`,
		integrationID, ev.ID).Scan(&status, &code, &resp)
	outcome := "failed"
	if status == "delivered" {
		outcome = "delivered"
		_ = s.MarkDeadLetterResolved(ctx, dlqID, "replayed")
	}
	var statusCode any
	if code != nil {
		statusCode = *code
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE integration_replays
		   SET outcome=$2, status_code=$3, response_body=$4, completed_at=now()
		 WHERE id=$1`, replayID, outcome, statusCode, resp); err != nil {
		return err
	}
	return nil
}

// ---------------- helpers ---------------------------------------------------

func stringFromPayload(p map[string]any, k string) (string, bool) {
	if p == nil {
		return "", false
	}
	v, ok := p[k]
	if !ok {
		return "", false
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	return fmt.Sprintf("%v", v), false
}

func stringValOr(p map[string]any, k, def string) string {
	if v, ok := stringFromPayload(p, k); ok {
		return v
	}
	return def
}

func numberFromPayload(p map[string]any, k string) float64 {
	if p == nil {
		return 0
	}
	v, ok := p[k]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

func uuidStrOrEmpty(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}
