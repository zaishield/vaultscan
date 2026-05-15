package parsers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// §15.7 — parsers for the seven tools added in migration 0036.
// Each parser produces info-or-higher findings with the scanner
// name pinned so the per-scanner dashboards count correctly.

// ----- sqlmap ---------------------------------------------------------------
//
// sqlmap default JSON output is in `*.csv` or the session file; the
// most stable JSON shape is from --output-dir=... --batch --json
// which dumps a doc per vulnerable parameter:
//   {"target":"...", "vulnerable":true, "techniques":["B","U","T"],
//    "place":"GET", "parameter":"id", "type":"boolean-based blind"}

func ParseSQLMap(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			Target     string   `json:"target"`
			Vulnerable bool     `json:"vulnerable"`
			Techniques []string `json:"techniques"`
			Place      string   `json:"place"`
			Parameter  string   `json:"parameter"`
			Type       string   `json:"type"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || !doc.Vulnerable {
			continue
		}
		f := base(ctx)
		f.Title = "SQL injection: " + doc.Place + " parameter '" + doc.Parameter + "'"
		f.Severity = "critical"
		f.Scanner = "sqlmap"
		f.ScanType = "web"
		f.CWE = "CWE-89"
		f.AffectedEndpoint = doc.Target
		f.EvidenceSummary = fmt.Sprintf("type=%s techniques=%v parameter=%s",
			doc.Type, doc.Techniques, doc.Parameter)
		out = append(out, f)
	}
	return out, nil
}

// ----- gobuster -------------------------------------------------------------
//
// Gobuster -o /dev/stdout -q -f -k -t 50 with --json gives:
//   {"url":"https://x/admin","status":401,"size":1234}

func ParseGobuster(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Size   int    `json:"size"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.URL == "" {
			continue
		}
		sev := "info"
		switch {
		case doc.Status == 200:
			sev = "medium"
		case doc.Status == 401 || doc.Status == 403:
			sev = "low"
		case doc.Status == 404:
			continue
		}
		f := base(ctx)
		f.Title = fmt.Sprintf("Hidden endpoint found: %s [%d]", doc.URL, doc.Status)
		f.Severity = sev
		f.Scanner = "gobuster"
		f.ScanType = "web"
		f.AffectedEndpoint = doc.URL
		f.EvidenceSummary = fmt.Sprintf("status=%d size=%d", doc.Status, doc.Size)
		out = append(out, f)
	}
	return out, nil
}

// ----- dirsearch ------------------------------------------------------------
//
// dirsearch --format=json --json-report=stdout:
//   {"info":{"args":...}, "results":[{"status":200, "path":"/admin",
//    "url":"...", "content-length":1234, "redirect":""}]}

func ParseDirsearch(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var doc struct {
		Results []struct {
			Status   int    `json:"status"`
			Path     string `json:"path"`
			URL      string `json:"url"`
			Length   int    `json:"content-length"`
			Redirect string `json:"redirect"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsers: dirsearch json: %w", err)
	}
	var out []findings.IngestInput
	for _, r := range doc.Results {
		if r.Status == 404 {
			continue
		}
		sev := "info"
		switch {
		case r.Status == 200:
			sev = "medium"
		case r.Status == 401 || r.Status == 403:
			sev = "low"
		}
		f := base(ctx)
		f.Title = fmt.Sprintf("Endpoint discovered: %s [%d]", r.URL, r.Status)
		f.Severity = sev
		f.Scanner = "dirsearch"
		f.ScanType = "web"
		f.AffectedEndpoint = r.URL
		f.EvidenceSummary = fmt.Sprintf("path=%s status=%d length=%d redirect=%s",
			r.Path, r.Status, r.Length, r.Redirect)
		out = append(out, f)
	}
	return out, nil
}

// ----- semgrep --------------------------------------------------------------
//
// `semgrep --json` produces one big doc with results[]:
//   {"results":[{"check_id":"...", "path":"src/app.py", "start":{"line":42},
//    "extra":{"severity":"ERROR", "message":"hardcoded secret", "metadata":{"cwe":["CWE-798"]}}}]}

func ParseSemgrep(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var doc struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Severity string `json:"severity"` // INFO | WARNING | ERROR
				Message  string `json:"message"`
				Metadata struct {
					CWE       []string `json:"cwe"`
					Confidence string  `json:"confidence"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsers: semgrep json: %w", err)
	}
	var out []findings.IngestInput
	for _, r := range doc.Results {
		sev := "info"
		switch strings.ToUpper(r.Extra.Severity) {
		case "ERROR":
			sev = "high"
		case "WARNING":
			sev = "medium"
		case "INFO":
			sev = "info"
		}
		cwe := ""
		if len(r.Extra.Metadata.CWE) > 0 {
			cwe = r.Extra.Metadata.CWE[0]
		}
		f := base(ctx)
		f.Title = "SAST finding: " + r.CheckID
		f.Severity = sev
		f.Scanner = "semgrep"
		f.ScanType = "code"
		f.CWE = cwe
		f.AffectedEndpoint = fmt.Sprintf("%s:%d", r.Path, r.Start.Line)
		f.EvidenceSummary = r.Extra.Message
		if r.Extra.Metadata.Confidence != "" {
			f.Confidence = strings.ToLower(r.Extra.Metadata.Confidence)
		}
		out = append(out, f)
	}
	return out, nil
}

// ----- gitleaks -------------------------------------------------------------
//
// gitleaks --report-format json --report-path /dev/stdout:
//   [{"Description":"...", "RuleID":"...", "File":"...", "Match":"...",
//     "Secret":"...", "Commit":"sha", "Author":"...", "Email":"..."}]
//
// Always emits "high" — exposed secrets are never an informational
// finding even if the corpus is internal.

func ParseGitleaks(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var doc []struct {
		Description string `json:"Description"`
		RuleID      string `json:"RuleID"`
		File        string `json:"File"`
		Commit      string `json:"Commit"`
		Author      string `json:"Author"`
		Email       string `json:"Email"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsers: gitleaks json: %w", err)
	}
	var out []findings.IngestInput
	for _, r := range doc {
		f := base(ctx)
		f.Title = "Secret detected: " + r.RuleID
		f.Severity = "high"
		f.Scanner = "gitleaks"
		f.ScanType = "secrets"
		f.CWE = "CWE-798"
		f.AffectedEndpoint = r.File
		f.EvidenceSummary = fmt.Sprintf("%s in commit %s by %s <%s>",
			r.Description, r.Commit, r.Author, r.Email)
		out = append(out, f)
	}
	return out, nil
}

// ----- hydra ----------------------------------------------------------------
//
// hydra output format -o /dev/stdout has plain-text lines like:
//   [PORT][PROTO] host: HOST   login: USER   password: PASS
// We emit critical findings — every successful login is platform-
// confirmed weak credentials, the most dangerous finding shape.

func ParseHydra(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") || !strings.Contains(line, "login:") {
			continue
		}
		f := base(ctx)
		f.Title = "Weak credentials confirmed (hydra)"
		f.Severity = "critical"
		f.Scanner = "hydra"
		f.ScanType = "network"
		f.CWE = "CWE-521"
		// Best-effort parse of "host: HOST" + "login: USER"
		fields := strings.Fields(line)
		host := ""
		for i, fld := range fields {
			if fld == "host:" && i+1 < len(fields) {
				host = fields[i+1]
			}
		}
		f.AffectedEndpoint = host
		f.EvidenceSummary = line
		out = append(out, f)
	}
	return out, nil
}

// ----- recon-ng -------------------------------------------------------------
//
// recon-ng output isn't JSON by default. The workflow exports rows
// from its modules; we accept the standard `--format=json` of
// `show <table>` for hosts / contacts / vulnerabilities. Hosts +
// contacts emit info findings (surface enumeration); vulnerabilities
// inherit their listed severity.

func ParseReconNG(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var doc struct {
		Module string                   `json:"module"`
		Rows   []map[string]interface{} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsers: recon-ng json: %w", err)
	}
	var out []findings.IngestInput
	for _, row := range doc.Rows {
		f := base(ctx)
		f.Scanner = "recon-ng"
		f.ScanType = "discovery"
		switch doc.Module {
		case "recon/hosts":
			host, _ := row["host"].(string)
			f.Title = "Host discovered: " + host
			f.Severity = "info"
			f.AffectedEndpoint = host
		case "recon/contacts":
			email, _ := row["email"].(string)
			f.Title = "Contact discovered: " + email
			f.Severity = "info"
			f.AffectedEndpoint = email
		case "recon/vulnerabilities":
			ref, _ := row["reference"].(string)
			sev, _ := row["category"].(string)
			f.Title = "Vulnerability surfaced: " + ref
			f.Severity = strings.ToLower(sev)
			if f.Severity == "" {
				f.Severity = "medium"
			}
			host, _ := row["host"].(string)
			f.AffectedEndpoint = host
		default:
			// Unknown module — still record but as info.
			f.Title = "recon-ng record: " + doc.Module
			f.Severity = "info"
		}
		body, _ := json.Marshal(row)
		f.EvidenceSummary = string(body)
		out = append(out, f)
	}
	return out, nil
}
