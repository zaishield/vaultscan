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
