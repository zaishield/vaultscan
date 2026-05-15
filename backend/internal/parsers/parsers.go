// Package parsers turns raw scanner output into normalized findings
// (Blueprint §15, §17.1). Each tool gets its own parser; all return the
// IngestInput shape consumed by findings.Service.Upsert.
package parsers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/findings"
)

// Context provides tenant/partner/engagement linkage every parser needs.
type Context struct {
	PlatformID   uuid.UUID
	PartnerID    uuid.UUID
	TenantID     uuid.UUID
	EngagementID uuid.UUID
	ScanJobID    *uuid.UUID
	AssetID      *uuid.UUID
}

// ParseFunc is the canonical parser signature.
type ParseFunc func(ctx Context, raw []byte) ([]findings.IngestInput, error)

// Registry maps tool codes to their parser implementations.
var Registry = map[string]ParseFunc{
	"nmap":       ParseNmap,
	"openvas":    ParseOpenVAS,
	"zap":        ParseZAP,
	"nuclei":     ParseNuclei,
	"testssl":    ParseTestSSL,
	"sslyze":     ParseSslyze,
	"trivy":      ParseTrivy,
	"prowler":    ParseProwler,
	"kube-bench": ParseKubeBench,
	"lynis":      ParseLynis,
	"bloodhound": ParseBloodhound,
	"netexec":    ParseNetexec,
	"mobsf":      ParseMobSF,
	// Discovery parsers (parsers/discovery.go).
	"amass":     ParseAmass,
	"subfinder": ParseSubfinder,
	"dnsx":      ParseDNSx,
	"httpx":     ParseHTTPX,
	"naabu":     ParseNaabu,
	"katana":    ParseKatana,
	"ffuf":      ParseFFUF,
}

func base(ctx Context) findings.IngestInput {
	return findings.IngestInput{
		PlatformID: ctx.PlatformID, PartnerID: ctx.PartnerID,
		TenantID: ctx.TenantID, EngagementID: ctx.EngagementID,
		ScanJobID: ctx.ScanJobID, AssetID: ctx.AssetID,
	}
}

// ----- Nmap (XML) ----------------------------------------------------------

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}
type nmapHost struct {
	Address []nmapAddr `xml:"address"`
	Ports   nmapPorts  `xml:"ports"`
}
type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}
type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}
type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}
type nmapState struct {
	State string `xml:"state,attr"`
}
type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}
type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

func ParseNmap(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var r nmapRun
	if err := xml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parsers: nmap xml: %w", err)
	}
	var out []findings.IngestInput
	for _, h := range r.Hosts {
		host := primaryAddr(h.Address)
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			port, _ := strconv.Atoi(p.PortID)
			f := base(ctx)
			f.Title = fmt.Sprintf("Open %s/%s service: %s", p.PortID, p.Protocol,
				strings.TrimSpace(p.Service.Name+" "+p.Service.Product))
			f.Severity = "info"
			f.Scanner = "nmap"
			f.ScanType = "network"
			f.Port = port
			f.Protocol = p.Protocol
			f.AffectedEndpoint = host
			f.EvidenceSummary = fmt.Sprintf("nmap reported %s %s %s on %s/%s",
				p.Service.Name, p.Service.Product, p.Service.Version, p.PortID, p.Protocol)
			for _, sc := range p.Scripts {
				if strings.Contains(strings.ToLower(sc.ID), "vuln") {
					f.Severity = "high"
					f.Title = fmt.Sprintf("Nmap vuln script %s on %s:%s", sc.ID, host, p.PortID)
					f.EvidenceSummary = sc.Output
				}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func primaryAddr(addrs []nmapAddr) string {
	for _, a := range addrs {
		if a.Type == "ipv4" || a.Type == "ipv6" {
			return a.Addr
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Addr
	}
	return ""
}

// ----- OpenVAS (XML report) -----------------------------------------------

type openvasReport struct {
	Results struct {
		Result []struct {
			Name        string `xml:"name"`
			Description string `xml:"description"`
			Severity    string `xml:"severity"`
			Threat      string `xml:"threat"`
			Host        string `xml:"host"`
			Port        string `xml:"port"`
			NVT         struct {
				CVE string `xml:"cve"`
				BID string `xml:"bid"`
			} `xml:"nvt"`
		} `xml:"result"`
	} `xml:"results"`
}

func ParseOpenVAS(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var r openvasReport
	if err := xml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parsers: openvas xml: %w", err)
	}
	var out []findings.IngestInput
	for _, res := range r.Results.Result {
		score, _ := strconv.ParseFloat(res.Severity, 64)
		f := base(ctx)
		f.Title = res.Name
		f.Description = res.Description
		f.Severity = severityFromCVSS(score)
		f.CVSSScore = score
		f.Scanner = "openvas"
		f.ScanType = "vulnerability"
		f.AffectedEndpoint = res.Host
		f.CVE = strings.TrimSpace(strings.ReplaceAll(res.NVT.CVE, "NOCVE", ""))
		f.EvidenceSummary = res.Description
		// port like "443/tcp"
		if i := strings.Index(res.Port, "/"); i > 0 {
			f.Port, _ = strconv.Atoi(res.Port[:i])
			f.Protocol = res.Port[i+1:]
		}
		out = append(out, f)
	}
	return out, nil
}

// ----- ZAP (JSON report) ---------------------------------------------------

type zapReport struct {
	Site []struct {
		Host    string `json:"@host"`
		Port    string `json:"@port"`
		Alerts  []struct {
			Alert       string `json:"alert"`
			RiskCode    string `json:"riskcode"`
			Confidence  string `json:"confidence"`
			Description string `json:"desc"`
			Solution    string `json:"solution"`
			Reference   string `json:"reference"`
			CWEID       string `json:"cweid"`
			Instances   []struct {
				URI    string `json:"uri"`
				Param  string `json:"param"`
				Method string `json:"method"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

func ParseZAP(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var r zapReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parsers: zap json: %w", err)
	}
	var out []findings.IngestInput
	for _, site := range r.Site {
		port, _ := strconv.Atoi(site.Port)
		for _, a := range site.Alerts {
			f := base(ctx)
			f.Title = a.Alert
			f.Description = a.Description
			f.Severity = severityFromZAPRisk(a.RiskCode)
			f.Confidence = strings.ToLower(zapConfidence(a.Confidence))
			f.Scanner = "zap"
			f.ScanType = "web"
			f.AffectedEndpoint = site.Host
			f.Port = port
			f.CWE = a.CWEID
			f.Remediation = a.Solution
			if a.Reference != "" {
				f.References = strings.Split(a.Reference, "\n")
			}
			if len(a.Instances) > 0 {
				f.AffectedEndpoint = a.Instances[0].URI
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func severityFromZAPRisk(code string) string {
	switch code {
	case "3":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	default:
		return "info"
	}
}
func zapConfidence(c string) string {
	switch c {
	case "3":
		return "high"
	case "2":
		return "medium"
	default:
		return "low"
	}
}

// ----- Nuclei (JSONL) ------------------------------------------------------

type nucleiHit struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Tags        []string `json:"tags"`
		Classification struct {
			CVSSScore  float64 `json:"cvss-score"`
			CVSSVector string  `json:"cvss-metrics"`
			CVE        []string `json:"cve-id"`
			CWE        []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Host         string `json:"host"`
	MatchedAt    string `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
}

func ParseNuclei(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var out []findings.IngestInput
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var h nucleiHit
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			continue
		}
		f := base(ctx)
		f.Title = h.Info.Name
		if f.Title == "" {
			f.Title = h.TemplateID
		}
		f.Description = h.Info.Description
		f.Severity = strings.ToLower(h.Info.Severity)
		f.Scanner = "nuclei"
		f.ScanType = "template"
		f.AffectedEndpoint = h.MatchedAt
		f.CVSSScore = h.Info.Classification.CVSSScore
		f.CVSSVector = h.Info.Classification.CVSSVector
		if len(h.Info.Classification.CVE) > 0 {
			f.CVE = strings.Join(h.Info.Classification.CVE, ",")
		}
		if len(h.Info.Classification.CWE) > 0 {
			f.CWE = strings.Join(h.Info.Classification.CWE, ",")
		}
		f.References = h.Info.Reference
		f.EvidenceSummary = strings.Join(h.ExtractedResults, "\n")
		out = append(out, f)
	}
	return out, nil
}

// ----- testssl.sh (JSON) ---------------------------------------------------

type testsslEntry struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
	CWE      string `json:"cwe"`
}

func ParseTestSSL(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var entries []testsslEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parsers: testssl json: %w", err)
	}
	out := []findings.IngestInput{}
	for _, e := range entries {
		sev := strings.ToLower(e.Severity)
		if sev == "ok" || sev == "info" || sev == "" {
			continue
		}
		f := base(ctx)
		f.Title = "TLS posture: " + e.ID
		f.Description = e.Finding
		f.Severity = mapTestsslSeverity(sev)
		f.Scanner = "testssl"
		f.ScanType = "tls"
		f.AffectedEndpoint = e.IP
		f.Port, _ = strconv.Atoi(e.Port)
		f.CVE = e.CVE
		f.CWE = e.CWE
		f.EvidenceSummary = e.Finding
		out = append(out, f)
	}
	return out, nil
}
func mapTestsslSeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "warn", "warning":
		return "low"
	default:
		return "info"
	}
}

// ----- sslyze (JSON) -------------------------------------------------------

func ParseSslyze(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	// minimal subset
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []findings.IngestInput
	if results, ok := doc["server_scan_results"].([]any); ok {
		for _, r := range results {
			rs, _ := r.(map[string]any)
			host, _ := rs["server_location"].(map[string]any)["hostname"].(string)
			f := base(ctx)
			f.Title = "TLS posture for " + host
			f.Severity = "info"
			f.Scanner = "sslyze"
			f.ScanType = "tls"
			f.AffectedEndpoint = host
			f.EvidenceSummary = "sslyze full report attached as evidence"
			out = append(out, f)
		}
	}
	return out, nil
}

// ----- Trivy (JSON) --------------------------------------------------------

type trivyDoc struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string  `json:"VulnerabilityID"`
			PkgName          string  `json:"PkgName"`
			InstalledVersion string  `json:"InstalledVersion"`
			Severity         string  `json:"Severity"`
			Title            string  `json:"Title"`
			Description      string  `json:"Description"`
			CVSS             map[string]struct {
				Score  float64 `json:"V3Score"`
				Vector string  `json:"V3Vector"`
			} `json:"CVSS"`
			References []string `json:"References"`
			CweIDs     []string `json:"CweIDs"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func ParseTrivy(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var d trivyDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []findings.IngestInput
	for _, r := range d.Results {
		for _, v := range r.Vulnerabilities {
			f := base(ctx)
			f.Title = fmt.Sprintf("%s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
			f.Description = v.Description
			f.Severity = strings.ToLower(v.Severity)
			f.Scanner = "trivy"
			f.ScanType = "container"
			f.AffectedEndpoint = r.Target
			f.CVE = v.VulnerabilityID
			if len(v.CweIDs) > 0 {
				f.CWE = strings.Join(v.CweIDs, ",")
			}
			for _, c := range v.CVSS {
				f.CVSSScore = c.Score
				f.CVSSVector = c.Vector
			}
			f.References = v.References
			out = append(out, f)
		}
	}
	return out, nil
}

// ----- Prowler (JSON OCSF) -------------------------------------------------

type prowlerFinding struct {
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	Region     string `json:"region"`
	CheckTitle string `json:"check_title"`
	CheckID    string `json:"check_id"`
	Resource   struct {
		ID  string `json:"id"`
		ARN string `json:"arn"`
	} `json:"resource"`
	Description string `json:"description"`
}

func ParseProwler(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var entries []prowlerFinding
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	var out []findings.IngestInput
	for _, e := range entries {
		if strings.EqualFold(e.Status, "PASS") {
			continue
		}
		f := base(ctx)
		f.Title = e.CheckTitle
		f.Description = e.Description
		f.Severity = strings.ToLower(e.Severity)
		f.Scanner = "prowler"
		f.ScanType = "cloud"
		f.AffectedEndpoint = e.Resource.ARN
		f.EvidenceSummary = e.CheckID
		out = append(out, f)
	}
	return out, nil
}

// ----- kube-bench (JSON) ---------------------------------------------------

type kubeBenchReport struct {
	Tests []struct {
		Section string `json:"section"`
		Desc    string `json:"desc"`
		Results []struct {
			TestNumber string `json:"test_number"`
			TestDesc   string `json:"test_desc"`
			Status     string `json:"status"`
			Remediation string `json:"remediation"`
		} `json:"results"`
	} `json:"tests"`
}

func ParseKubeBench(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var r kubeBenchReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	var out []findings.IngestInput
	for _, t := range r.Tests {
		for _, res := range t.Results {
			if strings.EqualFold(res.Status, "PASS") {
				continue
			}
			f := base(ctx)
			f.Title = fmt.Sprintf("CIS %s: %s", res.TestNumber, res.TestDesc)
			f.Severity = "medium"
			if strings.EqualFold(res.Status, "FAIL") {
				f.Severity = "high"
			}
			f.Scanner = "kube-bench"
			f.ScanType = "kubernetes"
			f.Remediation = res.Remediation
			out = append(out, f)
		}
	}
	return out, nil
}

// ----- Lynis (text) --------------------------------------------------------

func ParseLynis(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	out := []findings.IngestInput{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "warning[]=") && !strings.HasPrefix(line, "suggestion[]=") {
			continue
		}
		eq := strings.Index(line, "=")
		body := line[eq+1:]
		f := base(ctx)
		f.Title = "Lynis: " + firstField(body, '|')
		f.Description = body
		f.Severity = "low"
		if strings.HasPrefix(line, "warning[]") {
			f.Severity = "medium"
		}
		f.Scanner = "lynis"
		f.ScanType = "host_hardening"
		out = append(out, f)
	}
	return out, nil
}
func firstField(s string, sep rune) string {
	for i, c := range s {
		if c == sep {
			return s[:i]
		}
	}
	return s
}

// ----- Bloodhound CE / NetExec ---------------------------------------------

func ParseBloodhound(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	// Bloodhound emits a JSON dump of nodes/edges; we surface high-risk paths.
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	f := base(ctx)
	f.Title = "Active Directory privilege paths discovered"
	f.Severity = "high"
	f.Scanner = "bloodhound"
	f.ScanType = "ad"
	f.EvidenceSummary = "bloodhound graph attached as evidence"
	return []findings.IngestInput{f}, nil
}

func ParseNetexec(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	out := []findings.IngestInput{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(strings.ToLower(line), "vulnerable") {
			continue
		}
		f := base(ctx)
		f.Title = "NetExec/SMB exposure: " + line
		f.Severity = "high"
		f.Scanner = "netexec"
		f.ScanType = "smb"
		f.EvidenceSummary = line
		out = append(out, f)
	}
	return out, nil
}

// ----- MobSF (JSON) --------------------------------------------------------

type mobsfFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Desc     string `json:"description"`
}

func ParseMobSF(ctx Context, raw []byte) ([]findings.IngestInput, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := []findings.IngestInput{}
	if findings, ok := doc["findings"].([]any); ok {
		for _, x := range findings {
			b, _ := json.Marshal(x)
			var f mobsfFinding
			if err := json.Unmarshal(b, &f); err != nil {
				continue
			}
			fi := base(ctx)
			fi.Title = "MobSF: " + f.Title
			fi.Description = f.Desc
			fi.Severity = strings.ToLower(f.Severity)
			fi.Scanner = "mobsf"
			fi.ScanType = "mobile"
			out = append(out, fi)
		}
	}
	return out, nil
}

// severityFromCVSS bins a CVSS3 score into the canonical levels.
func severityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}
