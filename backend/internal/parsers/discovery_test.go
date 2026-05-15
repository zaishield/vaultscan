package parsers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testCtx() Context {
	return Context{
		PlatformID: uuid.New(), PartnerID: uuid.New(),
		TenantID: uuid.New(), EngagementID: uuid.New(),
	}
}

func TestParseAmass(t *testing.T) {
	raw := []byte(`{"name":"api.globex.example","domain":"globex.example","sources":["crtsh","cert"]}
{"name":"static.globex.example","domain":"globex.example","sources":["dnsdumpster"]}
`)
	out, err := ParseAmass(testCtx(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].AffectedEndpoint != "api.globex.example" || out[0].Scanner != "amass" {
		t.Fatalf("first finding wrong: %+v", out[0])
	}
	if !strings.Contains(out[0].EvidenceSummary, "crtsh") {
		t.Fatalf("evidence summary missing sources: %s", out[0].EvidenceSummary)
	}
}

func TestParseSubfinder(t *testing.T) {
	raw := []byte(`{"host":"api.globex.example","input":"globex.example","source":"crtsh"}
{"host":"www.globex.example","input":"globex.example","source":"dns"}
`)
	out, _ := ParseSubfinder(testCtx(), raw)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Severity != "info" {
		t.Fatalf("expected info severity, got %s", out[0].Severity)
	}
	if !strings.Contains(out[0].EvidenceSummary, "parent=globex.example") {
		t.Fatalf("parent missing: %s", out[0].EvidenceSummary)
	}
}

func TestParseDNSx_FlagsWildcard(t *testing.T) {
	raw := []byte(`{"host":"a.example","a":["1.2.3.4"],"wildcard":false,"resp_code":"NOERROR"}
{"host":"b.example","a":["5.6.7.8"],"wildcard":true,"resp_code":"NOERROR"}
`)
	out, _ := ParseDNSx(testCtx(), raw)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	// Non-wildcard host stays info.
	if out[0].Severity != "info" {
		t.Fatalf("non-wildcard must be info, got %s", out[0].Severity)
	}
	// Wildcard host bumps to low.
	if out[1].Severity != "low" {
		t.Fatalf("wildcard DNS must be low severity, got %s", out[1].Severity)
	}
	if !strings.Contains(out[1].Title, "Wildcard DNS") {
		t.Fatalf("wildcard title missing: %s", out[1].Title)
	}
}

func TestParseHTTPX_FlagsAdminInterfaces(t *testing.T) {
	raw := []byte(`{"url":"https://api.example/","status_code":200,"title":"Welcome","tech":["nginx"]}
{"url":"https://api.example/admin","status_code":200,"title":"Admin","tech":["wordpress"]}
{"url":"https://api.example/admin","status_code":401,"title":"Admin Login","tech":["wordpress"]}
{"url":"https://api.example/jenkins","status_code":200,"title":"Jenkins","tech":["jenkins"]}
`)
	out, _ := ParseHTTPX(testCtx(), raw)
	if len(out) != 4 {
		t.Fatalf("expected 4, got %d", len(out))
	}
	severities := map[string]string{}
	for _, f := range out {
		severities[f.AffectedEndpoint] = f.Severity
	}
	// Default 200 = info.
	if severities["https://api.example/"] != "info" {
		t.Fatalf("plain 200 should be info, got %s", severities["https://api.example/"])
	}
	// 200 on /admin → high.
	if !strings.Contains(out[1].Title, "Exposed admin") {
		t.Fatalf("expected admin-exposed title, got: %s", out[1].Title)
	}
	if out[1].Severity != "high" {
		t.Fatalf("200 on /admin must be high, got %s", out[1].Severity)
	}
	// 401 on /admin → medium.
	if out[2].Severity != "medium" {
		t.Fatalf("401 on /admin must be medium, got %s", out[2].Severity)
	}
	// /jenkins → high.
	if out[3].Severity != "high" {
		t.Fatalf("/jenkins must be high, got %s", out[3].Severity)
	}
}

func TestParseNaabu_FlagsHighRiskPorts(t *testing.T) {
	raw := []byte(`{"ip":"10.0.0.1","port":443,"protocol":"tcp","host":"app","service":"https"}
{"ip":"10.0.0.1","port":3389,"protocol":"tcp","host":"dc01","service":"rdp"}
{"ip":"10.0.0.1","port":6379,"protocol":"tcp","host":"cache","service":"redis"}
`)
	out, _ := ParseNaabu(testCtx(), raw)
	if len(out) != 3 {
		t.Fatalf("expected 3, got %d", len(out))
	}
	// 443 is normal — info.
	if out[0].Severity != "info" {
		t.Fatalf("443 should be info, got %s", out[0].Severity)
	}
	// 3389 (RDP) is high-risk.
	if out[1].Severity != "medium" {
		t.Fatalf("3389 (RDP) must be medium, got %s", out[1].Severity)
	}
	if !strings.Contains(out[1].Title, "High-risk port") {
		t.Fatalf("3389 title missing high-risk marker: %s", out[1].Title)
	}
	// 6379 (Redis) is high-risk.
	if out[2].Severity != "medium" {
		t.Fatalf("6379 (Redis) must be medium, got %s", out[2].Severity)
	}
}

func TestParseKatana_EmitsURLsCrawled(t *testing.T) {
	raw := []byte(`{"request":{"endpoint":"https://app/login","method":"GET"},"response":{"status_code":200}}
{"request":{"endpoint":"https://app/api/users","method":"GET"},"response":{"status_code":401}}
`)
	out, _ := ParseKatana(testCtx(), raw)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Scanner != "katana" || out[0].ScanType != "web" {
		t.Fatalf("wrong scanner/scantype: %+v", out[0])
	}
	if !strings.Contains(out[1].EvidenceSummary, "status=401") {
		t.Fatalf("status missing in evidence: %s", out[1].EvidenceSummary)
	}
}

func TestParseFFUF_SeverityByStatusCode(t *testing.T) {
	raw := []byte(`{
		"results": [
			{"url":"https://app/admin","status":200,"length":1234,"input":{"FUZZ":"admin"}},
			{"url":"https://app/.git","status":403,"length":42,"input":{"FUZZ":".git"}},
			{"url":"https://app/notfound","status":404,"length":0,"input":{"FUZZ":"notfound"}},
			{"url":"https://app/api","status":405,"length":0,"input":{"FUZZ":"api"}}
		]
	}`)
	out, err := ParseFFUF(testCtx(), raw)
	if err != nil {
		t.Fatal(err)
	}
	// 404 must be filtered.
	if len(out) != 3 {
		t.Fatalf("expected 3 findings (404 filtered), got %d", len(out))
	}
	sevByURL := map[string]string{}
	for _, f := range out {
		sevByURL[f.AffectedEndpoint] = f.Severity
	}
	if sevByURL["https://app/admin"] != "medium" {
		t.Fatalf("200 hit expected medium, got %s", sevByURL["https://app/admin"])
	}
	if sevByURL["https://app/.git"] != "low" {
		t.Fatalf("403 hit expected low, got %s", sevByURL["https://app/.git"])
	}
	if sevByURL["https://app/api"] != "info" {
		t.Fatalf("405 hit expected info, got %s", sevByURL["https://app/api"])
	}
}

func TestParseFFUF_MalformedRejected(t *testing.T) {
	if _, err := ParseFFUF(testCtx(), []byte(`not json`)); err == nil {
		t.Fatal("malformed JSON must error")
	}
}

// TestJSONLinesTolerantOfNoise: blank lines, comments, trailing newline.
func TestJSONLinesTolerantOfNoise(t *testing.T) {
	raw := []byte("\n  \n# a comment that's not json\n{\"host\":\"a\"}\n\n{\"host\":\"b\"}\n")
	lines := jsonLines(raw)
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d", len(lines))
	}
}

// TestRegistry_DiscoveryToolsPresent: scanner-worker drops findings
// silently if a tool isn't registered, so this regression test makes
// sure none of the seven new parsers get accidentally unregistered.
func TestRegistry_DiscoveryToolsPresent(t *testing.T) {
	for _, tool := range []string{"amass", "subfinder", "dnsx", "httpx", "naabu", "katana", "ffuf"} {
		if _, ok := Registry[tool]; !ok {
			t.Fatalf("parsers.Registry[%q] missing — scanner-worker will skip %s output", tool, tool)
		}
	}
}
