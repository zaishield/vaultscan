package parsers

import (
	"strings"
	"testing"
)

func TestParseSQLMap(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"target":"https://x/?id=1","vulnerable":true,"techniques":["B"],"place":"GET","parameter":"id","type":"boolean-based blind"}` + "\n")
	out, _ := ParseSQLMap(testCtx(), raw)
	if len(out) != 1 || out[0].Severity != "critical" || out[0].CWE != "CWE-89" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestParseGobuster_FiltersAndBumps(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"url":"https://x/admin","status":200,"size":1024}
{"url":"https://x/missing","status":404,"size":0}
{"url":"https://x/.env","status":403,"size":42}
`)
	out, _ := ParseGobuster(testCtx(), raw)
	if len(out) != 2 {
		t.Fatalf("expected 2 (404 filtered), got %d", len(out))
	}
	got := map[string]string{}
	for _, f := range out {
		got[f.AffectedEndpoint] = f.Severity
	}
	if got["https://x/admin"] != "medium" {
		t.Fatalf("200 should be medium, got %s", got["https://x/admin"])
	}
	if got["https://x/.env"] != "low" {
		t.Fatalf("403 should be low, got %s", got["https://x/.env"])
	}
}

func TestParseDirsearch(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"results":[
		{"status":200,"path":"/admin","url":"https://x/admin","content-length":12,"redirect":""},
		{"status":404,"path":"/no","url":"https://x/no","content-length":0,"redirect":""}
	]}`)
	out, _ := ParseDirsearch(testCtx(), raw)
	if len(out) != 1 {
		t.Fatalf("expected 1, got %d", len(out))
	}
	if out[0].Severity != "medium" {
		t.Fatalf("200 should be medium, got %s", out[0].Severity)
	}
}

func TestParseSemgrep_SeverityMap(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"results":[
		{"check_id":"py.flask.security","path":"app.py","start":{"line":42},
		 "extra":{"severity":"ERROR","message":"hardcoded secret",
		          "metadata":{"cwe":["CWE-798"],"confidence":"HIGH"}}},
		{"check_id":"py.style","path":"app.py","start":{"line":1},
		 "extra":{"severity":"INFO","message":"style"}}
	]}`)
	out, _ := ParseSemgrep(testCtx(), raw)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Severity != "high" || out[0].CWE != "CWE-798" {
		t.Fatalf("ERROR semgrep finding wrong: %+v", out[0])
	}
	if out[1].Severity != "info" {
		t.Fatalf("INFO semgrep finding wrong: %s", out[1].Severity)
	}
}

func TestParseGitleaks_AlwaysHigh(t *testing.T) {
	t.Parallel()
	raw := []byte(`[{"Description":"AWS key","RuleID":"aws-key","File":"src/keys.yaml",
	  "Commit":"abc","Author":"dev","Email":"d@x"}]`)
	out, _ := ParseGitleaks(testCtx(), raw)
	if len(out) != 1 || out[0].Severity != "high" || out[0].CWE != "CWE-798" {
		t.Fatalf("gitleaks must always emit high+CWE-798: %+v", out)
	}
}

func TestParseHydra_ExtractsHostAndIsCritical(t *testing.T) {
	t.Parallel()
	raw := []byte(`[22][ssh] host: 10.0.0.5   login: admin   password: hunter2
[80][http] host: 10.0.0.6   login: root    password: 12345
`)
	out, _ := ParseHydra(testCtx(), raw)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Severity != "critical" {
		t.Fatal("hydra success must be critical")
	}
	if out[0].AffectedEndpoint != "10.0.0.5" {
		t.Fatalf("host parse: %q", out[0].AffectedEndpoint)
	}
}

func TestParseReconNG_RoutesByModule(t *testing.T) {
	t.Parallel()
	for module, want := range map[string]string{
		"recon/hosts":           "Host discovered",
		"recon/contacts":        "Contact discovered",
		"recon/vulnerabilities": "Vulnerability surfaced",
	} {
		var body string
		switch module {
		case "recon/hosts":
			body = `{"module":"recon/hosts","rows":[{"host":"x.example"}]}`
		case "recon/contacts":
			body = `{"module":"recon/contacts","rows":[{"email":"e@x"}]}`
		case "recon/vulnerabilities":
			body = `{"module":"recon/vulnerabilities","rows":[{"reference":"CVE-2024-1","category":"high","host":"x"}]}`
		}
		out, _ := ParseReconNG(testCtx(), []byte(body))
		if len(out) != 1 {
			t.Fatalf("%s: expected 1, got %d", module, len(out))
		}
		if !strings.HasPrefix(out[0].Title, want) {
			t.Fatalf("%s: title %q doesn't start with %q", module, out[0].Title, want)
		}
	}
}

func TestRegistry_DevSecToolsPresent(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"sqlmap", "gobuster", "dirsearch", "semgrep", "gitleaks", "hydra", "recon-ng"} {
		if _, ok := Registry[tool]; !ok {
			t.Fatalf("parsers.Registry[%q] missing", tool)
		}
	}
}
