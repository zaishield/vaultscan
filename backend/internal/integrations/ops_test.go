package integrations

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// Outbound integrations are the bridge to customer ticketing / SIEM
// systems. The payload-build functions are pure: feeding them an
// eventbus.Event and a config map yields the exact bytes we POST to
// jira / servicenow / slack / teams or emit as CEF / LEEF. A regression
// here breaks ingest at the customer end without any error on our
// side, so we lock the payload shape with explicit unit tests.

func sampleEvent() eventbus.Event {
	tenant := uuid.MustParse("00000000-0000-0000-0000-0000000000c1")
	partner := uuid.MustParse("00000000-0000-0000-0000-0000000000b1")
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	return eventbus.Event{
		ID:        id,
		Type:      "finding.created",
		TenantID:  &tenant,
		PartnerID: &partner,
		Payload: map[string]any{
			"severity":   "critical",
			"cve":        "CVE-2024-12345",
			"cvss_score": 9.8,
			"title":      "SSRF in profile service",
		},
	}
}

func TestBuildJiraIssue_RequiredFields(t *testing.T) {
	t.Parallel()
	out, err := BuildJiraIssue(sampleEvent(), map[string]any{
		"project_key": "ZAI",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	fields := got["fields"].(map[string]any)
	if proj := fields["project"].(map[string]any)["key"]; proj != "ZAI" {
		t.Errorf("project.key=%v want ZAI", proj)
	}
	if it := fields["issuetype"].(map[string]any)["name"]; it != "Bug" {
		t.Errorf("issuetype.name=%v want Bug (default)", it)
	}
	if pri := fields["priority"].(map[string]any)["name"]; pri != "Highest" {
		t.Errorf("priority.name=%v want Highest", pri)
	}
	if sum := fields["summary"]; sum != "SSRF in profile service" {
		t.Errorf("summary=%v want SSRF…", sum)
	}
}

func TestBuildJiraIssue_RejectsMissingProjectKey(t *testing.T) {
	t.Parallel()
	if _, err := BuildJiraIssue(sampleEvent(), map[string]any{}, ""); err == nil {
		t.Fatal("missing project_key should error")
	}
}

func TestBuildJiraIssue_CustomFieldMapping(t *testing.T) {
	t.Parallel()
	out, _ := BuildJiraIssue(sampleEvent(), map[string]any{
		"project_key": "ZAI",
		"custom_fields": map[string]any{
			"cve":      "customfield_10001",
			"cvss":     "customfield_10002",
			"severity": "customfield_10003",
		},
	}, "Vulnerability")
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	fields := got["fields"].(map[string]any)
	if fields["customfield_10001"] != "CVE-2024-12345" {
		t.Errorf("cve cf mapping wrong: %v", fields["customfield_10001"])
	}
	if fields["customfield_10003"] != "critical" {
		t.Errorf("severity cf mapping wrong: %v", fields["customfield_10003"])
	}
}

func TestJiraPriority_Mapping(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"critical": "Highest", "high": "High", "medium": "Medium",
		"low": "Low", "info": "Lowest", "weird": "Lowest", "": "Lowest",
	}
	for sev, want := range cases {
		if got := jiraPriority(sev); got != want {
			t.Errorf("jiraPriority(%q)=%q want %q", sev, got, want)
		}
	}
}

func TestBuildServiceNowIncident_UrgencyFromSeverity(t *testing.T) {
	t.Parallel()
	out, _ := BuildServiceNowIncident(sampleEvent(), map[string]any{"caller_id": "vaultscan-svc"})
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["urgency"].(float64) != 1 {
		t.Errorf("critical → urgency=%v want 1", got["urgency"])
	}
	if got["impact"].(float64) != 1 {
		t.Errorf("impact=%v want 1", got["impact"])
	}
	if got["category"] != "Security" {
		t.Errorf("category=%v want Security", got["category"])
	}
	if got["caller_id"] != "vaultscan-svc" {
		t.Errorf("caller_id=%v", got["caller_id"])
	}
}

func TestSnowUrgency_Mapping(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 4, "": 4,
	}
	for sev, want := range cases {
		if got := snowUrgency(sev); got != want {
			t.Errorf("snowUrgency(%q)=%d want %d", sev, got, want)
		}
	}
}

func TestBuildCEF_HeaderAndExtensions(t *testing.T) {
	t.Parallel()
	out := BuildCEF(sampleEvent())
	if !strings.HasPrefix(out, "CEF:0|ZAISHIELD|VAULTSCAN|1.0|finding.created|") {
		t.Errorf("CEF header malformed: %q", out)
	}
	if !strings.Contains(out, "|10|") {
		t.Errorf("severity should be 10 for critical: %q", out)
	}
	if !strings.Contains(out, "cs2=CVE-2024-12345") {
		t.Errorf("CVE not in extensions: %q", out)
	}
	if !strings.Contains(out, "cn1=9.8") {
		t.Errorf("CVSS not in extensions: %q", out)
	}
	// Tenant must be present as cs1
	if !strings.Contains(out, "cs1=") {
		t.Errorf("tenant_id missing: %q", out)
	}
}

func TestBuildCEF_EscapesReservedChars(t *testing.T) {
	t.Parallel()
	ev := sampleEvent()
	ev.Payload["title"] = `Pipe|in|title and = in body`
	ev.Type = "alert|with|pipe"
	out := BuildCEF(ev)
	// Header escapes `|` as `\|`
	if !strings.Contains(out, `alert\|with\|pipe`) {
		t.Errorf("CEF header pipe not escaped: %q", out)
	}
	// Extension values escape `=` as `\=`
	if strings.Contains(out, `title=Pipe|in|title and = in body`) {
		t.Errorf("CEF extension `=` not escaped: %q", out)
	}
}

func TestBuildLEEF_HeaderAndDelimiter(t *testing.T) {
	t.Parallel()
	out := BuildLEEF(sampleEvent())
	if !strings.HasPrefix(out, "LEEF:2.0|ZAISHIELD|VAULTSCAN|1.0|finding.created|^|") {
		t.Errorf("LEEF header malformed: %q", out)
	}
	if !strings.Contains(out, "severity=critical") {
		t.Errorf("severity missing: %q", out)
	}
	if !strings.Contains(out, "cve=CVE-2024-12345") {
		t.Errorf("cve missing: %q", out)
	}
}

func TestNumericSeverityCEF(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1, "": 1,
	}
	for s, want := range cases {
		if got := numericSeverityCEF(s); got != want {
			t.Errorf("numericSeverityCEF(%q)=%d want %d", s, got, want)
		}
	}
}

func TestCEFFormatExtensions_DeterministicOrder(t *testing.T) {
	t.Parallel()
	exts := map[string]string{"z": "1", "a": "2", "m": "3"}
	got := formatCEFExtensions(exts)
	if got != "a=2 m=3 z=1" {
		t.Errorf("formatCEFExtensions not sorted: %q", got)
	}
}

func TestLEEFFormatExtensions_DeterministicOrder(t *testing.T) {
	t.Parallel()
	exts := map[string]string{"z": "1", "a": "2"}
	got := formatLEEFExtensions(exts)
	if got != "a=2^z=1" {
		t.Errorf("formatLEEFExtensions not sorted: %q", got)
	}
}

// Fuzz targets — payload builders ingest event payloads that contain
// fields an attacker could control (CVE descriptions, finding titles).
// A panic in CEF / LEEF escape would break the SIEM pipeline.
func FuzzBuildCEF(f *testing.F) {
	seeds := [][3]string{
		{"finding.created", "critical", "CVE-2024-0001"},
		{"alert|x", "high", ""},
		{"\nnewline\n", "medium", "CVE\\backslash"},
		{"=eq=", "low", "with|pipe"},
		{"", "", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, evType, severity, cve string) {
		ev := sampleEvent()
		ev.Type = evType
		ev.Payload = map[string]any{"severity": severity, "cve": cve}
		out := BuildCEF(ev)
		// Output must start with the header prefix and be a single line
		if !strings.HasPrefix(out, "CEF:0|") {
			t.Fatalf("CEF header missing: %q", out)
		}
		if strings.Contains(out, "\n") {
			t.Fatalf("CEF output contains newline: %q", out)
		}
	})
}

func FuzzBuildLEEF(f *testing.F) {
	seeds := []string{"", "with\nnewline", "x^y", "==", "{}"}
	for _, s := range seeds {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, title, cve string) {
		ev := sampleEvent()
		ev.Payload = map[string]any{"title": title, "cve": cve}
		out := BuildLEEF(ev)
		if !strings.HasPrefix(out, "LEEF:2.0|") {
			t.Fatalf("LEEF header missing: %q", out)
		}
		if strings.ContainsAny(out, "\n\r") {
			t.Fatalf("LEEF output contains literal newline: %q", out)
		}
	})
}
