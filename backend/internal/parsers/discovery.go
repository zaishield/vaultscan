package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// The seven parsers in this file all consume JSONL output from
// ProjectDiscovery-style tools (one JSON object per line). They emit
// info-level "asset surfaced" findings so the executive dashboard's
// attack-surface growth metric has a stable source — and so a sudden
// spike of discovered hosts shows up in the SLA/dashboard without the
// operator having to query the assets table directly.
//
// For genuine vulnerability detection, downstream tools (nuclei, nmap,
// trivy) take the discovered surface as their target list.

// ----- amass --------------------------------------------------------------
//
// Amass emits a JSON document per line:
//   {"name":"api.example.com","domain":"example.com","sources":["crtsh","cert"]}

func ParseAmass(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			Name    string   `json:"name"`
			Domain  string   `json:"domain"`
			Sources []string `json:"sources"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.Name == "" {
			continue
		}
		f := base(ctx)
		f.Title = "Subdomain discovered: " + doc.Name
		f.Severity = "info"
		f.Scanner = "amass"
		f.ScanType = "discovery"
		f.AffectedEndpoint = doc.Name
		f.EvidenceSummary = "discovered via " + strings.Join(doc.Sources, ", ")
		out = append(out, f)
	}
	return out, nil
}

// ----- subfinder ----------------------------------------------------------
//
// Subfinder emits  {"host":"api.example.com","input":"example.com","source":"crtsh"}.

func ParseSubfinder(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			Host   string `json:"host"`
			Source string `json:"source"`
			Input  string `json:"input"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.Host == "" {
			continue
		}
		f := base(ctx)
		f.Title = "Subdomain discovered: " + doc.Host
		f.Severity = "info"
		f.Scanner = "subfinder"
		f.ScanType = "discovery"
		f.AffectedEndpoint = doc.Host
		f.EvidenceSummary = "source=" + doc.Source + " parent=" + doc.Input
		out = append(out, f)
	}
	return out, nil
}

// ----- dnsx ---------------------------------------------------------------
//
// dnsx emits one JSON per host with resolution details:
//   {"host":"api.example.com","a":["203.0.113.10"],"cname":["api-lb.example.com"],
//    "wildcard":false,"resp_code":"NOERROR"}
//
// A wildcard=true response is flagged as low-severity because it can
// indicate misconfigured DNS that hides real services.

func ParseDNSx(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			Host     string   `json:"host"`
			A        []string `json:"a"`
			CNAME    []string `json:"cname"`
			Wildcard bool     `json:"wildcard"`
			RespCode string   `json:"resp_code"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.Host == "" {
			continue
		}
		f := base(ctx)
		f.Title = "DNS resolution: " + doc.Host
		f.Severity = "info"
		f.Scanner = "dnsx"
		f.ScanType = "discovery"
		f.AffectedEndpoint = doc.Host
		f.EvidenceSummary = fmt.Sprintf("A=%v CNAME=%v code=%s",
			doc.A, doc.CNAME, doc.RespCode)
		if doc.Wildcard {
			f.Title = "Wildcard DNS detected on " + doc.Host
			f.Severity = "low"
		}
		out = append(out, f)
	}
	return out, nil
}

// ----- httpx --------------------------------------------------------------
//
// httpx emits  {"url":"https://api.example.com","status_code":200,
//    "title":"Login","tech":["nginx"],"webserver":"nginx",
//    "tls":{"subject_an":["api.example.com"]}}.
//
// We flag exposed-admin signals (status==401/403 paired with admin-y
// titles) as medium, and 200s on /admin or /jenkins as high.

func ParseHTTPX(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			URL        string   `json:"url"`
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			Tech       []string `json:"tech"`
			WebServer  string   `json:"webserver"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.URL == "" {
			continue
		}
		sev := "info"
		title := fmt.Sprintf("HTTP service: %s [%d]", doc.URL, doc.StatusCode)
		lower := strings.ToLower(doc.URL + " " + doc.Title)
		switch {
		case doc.StatusCode == 200 &&
			(strings.Contains(lower, "/admin") || strings.Contains(lower, "/jenkins") ||
				strings.Contains(lower, "/wp-admin") || strings.Contains(lower, "phpmyadmin")):
			sev = "high"
			title = "Exposed admin interface: " + doc.URL
		case (doc.StatusCode == 401 || doc.StatusCode == 403) &&
			strings.Contains(lower, "admin"):
			sev = "medium"
			title = "Authenticated admin interface exposed: " + doc.URL
		}
		f := base(ctx)
		f.Title = title
		f.Severity = sev
		f.Scanner = "httpx"
		f.ScanType = "discovery"
		f.AffectedEndpoint = doc.URL
		f.EvidenceSummary = fmt.Sprintf("status=%d title=%q tech=%v server=%s",
			doc.StatusCode, doc.Title, doc.Tech, doc.WebServer)
		out = append(out, f)
	}
	return out, nil
}

// ----- naabu --------------------------------------------------------------
//
// naabu emits  {"ip":"203.0.113.10","port":443,"protocol":"tcp",
//    "host":"api.example.com","service":"https"}.

func ParseNaabu(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Host     string `json:"host"`
			Service  string `json:"service"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.Port == 0 {
			continue
		}
		endpoint := doc.Host
		if endpoint == "" {
			endpoint = doc.IP
		}
		f := base(ctx)
		f.Title = fmt.Sprintf("Open port %d/%s%s",
			doc.Port, doc.Protocol, optService(doc.Service))
		f.Severity = "info"
		f.Scanner = "naabu"
		f.ScanType = "network"
		f.Port = doc.Port
		f.Protocol = doc.Protocol
		f.AffectedEndpoint = endpoint
		f.EvidenceSummary = fmt.Sprintf("ip=%s service=%s", doc.IP, doc.Service)
		// Risky ports get a one-step severity bump so the dashboard
		// surfaces them above pure discovery noise.
		if isHighRiskPort(doc.Port) {
			f.Severity = "medium"
			f.Title = "High-risk port " + strconv.Itoa(doc.Port) + " exposed on " + endpoint
		}
		out = append(out, f)
	}
	return out, nil
}

func isHighRiskPort(p int) bool {
	switch p {
	case 21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017:
		return true
	}
	return false
}

func optService(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// ----- katana -------------------------------------------------------------
//
// katana with -jc emits  {"request":{"endpoint":"https://app/path"},
//    "response":{"status_code":200,"body_preview":"..."}}.
//
// We emit one info finding per discovered URL so the scope-creep
// dashboard can see how the crawl spread.

func ParseKatana(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range jsonLines(raw) {
		var doc struct {
			Request struct {
				Endpoint string `json:"endpoint"`
				Method   string `json:"method"`
			} `json:"request"`
			Response struct {
				StatusCode int `json:"status_code"`
			} `json:"response"`
		}
		if err := json.Unmarshal(line, &doc); err != nil || doc.Request.Endpoint == "" {
			continue
		}
		f := base(ctx)
		f.Title = fmt.Sprintf("URL crawled: %s [%d]", doc.Request.Endpoint, doc.Response.StatusCode)
		f.Severity = "info"
		f.Scanner = "katana"
		f.ScanType = "web"
		f.AffectedEndpoint = doc.Request.Endpoint
		f.EvidenceSummary = fmt.Sprintf("method=%s status=%d",
			doc.Request.Method, doc.Response.StatusCode)
		out = append(out, f)
	}
	return out, nil
}

// ----- ffuf ---------------------------------------------------------------
//
// ffuf emits one big JSON doc with "results": [...]. Each result has
// {input:{FUZZ:"admin"}, url, status, length}.

func ParseFFUF(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var doc struct {
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Length int    `json:"length"`
			Input  map[string]string `json:"input"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsers: ffuf json: %w", err)
	}
	var out []findings.IngestInput
	for _, r := range doc.Results {
		// Only the "found" results matter — ffuf filters most noise itself,
		// but as a defensive measure ignore 404s.
		if r.Status == 404 {
			continue
		}
		sev := "info"
		switch {
		case r.Status == 200:
			sev = "medium" // a 200 on a fuzzed path is interesting by default
		case r.Status == 401 || r.Status == 403:
			sev = "low" // exists but protected
		}
		f := base(ctx)
		f.Title = fmt.Sprintf("Hidden endpoint found: %s [%d]", r.URL, r.Status)
		f.Severity = sev
		f.Scanner = "ffuf"
		f.ScanType = "web"
		f.AffectedEndpoint = r.URL
		f.EvidenceSummary = fmt.Sprintf("status=%d length=%d fuzz=%v",
			r.Status, r.Length, r.Input)
		out = append(out, f)
	}
	return out, nil
}

// jsonLines splits a JSONL byte slice into per-line objects, tolerant of
// blank lines + trailing newlines. Used by every JSONL-shaped parser
// above.
func jsonLines(raw []byte) [][]byte {
	var out [][]byte
	s := bufio.NewScanner(bytes.NewReader(raw))
	// Bump the buffer so a single 4MB JSON line doesn't blow up the
	// default 64K scanner cap (some httpx responses include body_preview).
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		// Copy the slice — Scanner reuses its buffer between calls.
		cp := make([]byte, len(line))
		copy(cp, line)
		out = append(out, cp)
	}
	return out
}
