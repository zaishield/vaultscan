package parsers

import (
	"testing"

	"github.com/google/uuid"
)

// Each parser is exercised against a tiny, realistic snippet to confirm it
// produces normalized findings the canonical model can ingest.
func ctxFor() Context {
	return Context{
		PlatformID: uuid.New(), PartnerID: uuid.New(),
		TenantID: uuid.New(), EngagementID: uuid.New(),
	}
}

func TestParseNmap(t *testing.T) {
	t.Parallel()
	xml := `<?xml version="1.0"?><nmaprun>
		<host><address addr="10.0.0.1" addrtype="ipv4"/>
		  <ports>
		    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
		    <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
		  </ports>
		</host></nmaprun>`
	out, err := ParseNmap(ctxFor(), []byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 open port, got %d", len(out))
	}
	if out[0].Port != 22 || out[0].Protocol != "tcp" {
		t.Fatalf("bad parse: %+v", out[0])
	}
}

func TestParseNuclei(t *testing.T) {
	t.Parallel()
	body := `{"template-id":"test","info":{"name":"Test Vuln","severity":"high"},"host":"https://x","matched-at":"https://x"}`
	out, err := ParseNuclei(ctxFor(), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Severity != "high" || out[0].Scanner != "nuclei" {
		t.Fatalf("bad: %+v", out)
	}
}

func TestParseZAP(t *testing.T) {
	t.Parallel()
	body := `{"site":[{"@host":"x","@port":"443","alerts":[
	  {"alert":"XSS","riskcode":"3","confidence":"3","desc":"d","solution":"s","reference":"r","cweid":"79",
	   "instances":[{"uri":"https://x","param":"q","method":"GET"}]}]}]}`
	out, err := ParseZAP(ctxFor(), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Severity != "high" {
		t.Fatalf("bad: %+v", out)
	}
}

func TestParseTestSSL(t *testing.T) {
	t.Parallel()
	body := `[{"id":"weak_cipher","ip":"10.0.0.1","port":"443","severity":"high","finding":"weak"}]`
	out, err := ParseTestSSL(ctxFor(), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ScanType != "tls" {
		t.Fatalf("bad: %+v", out)
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	t.Parallel()
	cases := map[float64]string{9.5: "critical", 7.5: "high", 5.0: "medium", 1.0: "low", 0: "info"}
	for s, want := range cases {
		if got := severityFromCVSS(s); got != want {
			t.Fatalf("severityFromCVSS(%v) = %q, want %q", s, got, want)
		}
	}
}

// Bloodhound used to be a single-line hardcoded "AD privilege paths
// discovered" stub regardless of content. These tests verify the
// rewrite produces real, content-derived findings.

func TestParseBloodhound_RealEdgesProduceFindings(t *testing.T) {
	t.Parallel()
	dump := `{
		"meta": {"type": "edges", "count": 150},
		"nodes": [
			{"label": "User", "props": {"name": "alice"}},
			{"label": "Group", "props": {"name": "Domain Admins"}}
		],
		"edges": [
			{"edge_type": "AddMember", "source": "u1", "target": "g1"},
			{"edge_type": "AddMember", "source": "u2", "target": "g1"},
			{"edge_type": "GenericAll", "source": "u3", "target": "g1"}
		]
	}`
	out, err := ParseBloodhound(Context{}, []byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected one finding per high-risk edge kind, got 0")
	}
	// Should have findings for AddMember and GenericAll.
	gotKinds := map[string]bool{}
	for _, f := range out {
		gotKinds[f.Title] = true
	}
	if !gotKinds["Active Directory attack path: AddMember"] {
		t.Errorf("missing AddMember finding: %+v", gotKinds)
	}
	if !gotKinds["Active Directory attack path: GenericAll"] {
		t.Errorf("missing GenericAll finding: %+v", gotKinds)
	}
}

func TestParseBloodhound_EmptyGraphIsInfo(t *testing.T) {
	t.Parallel()
	out, err := ParseBloodhound(Context{}, []byte(`{"nodes":[],"edges":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Severity != "info" {
		t.Errorf("expected single info finding for empty graph, got %+v", out)
	}
}

func TestParseBloodhound_NoHighRiskEdgesIsInfo(t *testing.T) {
	t.Parallel()
	// Graph populated but no privileged edges.
	dump := `{
		"nodes": [{"label": "User", "props": {}}],
		"edges": [{"edge_type": "MemberOf", "source": "u1", "target": "g1"}]
	}`
	out, _ := ParseBloodhound(Context{}, []byte(dump))
	if len(out) != 1 || out[0].Severity != "info" {
		t.Errorf("graph without risky edges should produce one info finding, got %+v", out)
	}
}

func TestParseBloodhound_MalformedInputIsSoftFailure(t *testing.T) {
	t.Parallel()
	// Not valid JSON. The old parser returned a hardcoded high-sev
	// finding regardless; the new parser returns an info finding
	// describing the parse failure so ops can investigate.
	out, _ := ParseBloodhound(Context{}, []byte(`not json {{`))
	if len(out) != 1 || out[0].Severity != "info" {
		t.Errorf("malformed input should produce one info finding, got %+v", out)
	}
}

// Parser-DoS guards: parsers.Lookup wraps every parser with input-
// size and finding-count caps. These tests exercise the limits.

func TestParserDoS_RefusesOversizedInput(t *testing.T) {
	t.Parallel()
	// Find any parser via Lookup; we don't care which — guardSize
	// runs before parser-specific code.
	p, ok := Lookup("nmap")
	if !ok {
		t.Fatal("nmap parser missing")
	}
	huge := make([]byte, MaxParserInputBytes+1)
	if _, err := p(Context{}, huge); err == nil {
		t.Error("expected ErrParserInputTooLarge for oversize input")
	}
}
