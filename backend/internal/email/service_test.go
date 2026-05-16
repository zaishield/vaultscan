package email

import (
	"context"
	"strings"
	"testing"
)

// Email template rendering takes operator-authored Go templates +
// variables that include attacker-influenced strings (finding titles,
// scope target hostnames). We test the pure renderString path and
// the MemoryTransport contract used by tests across the platform.

func TestRenderString_EmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	got, err := renderString("subj", "", map[string]any{"x": "y"})
	if err != nil || got != "" {
		t.Errorf("renderString(empty)=(%q,%v) want (\"\", nil)", got, err)
	}
}

func TestRenderString_InterpolatesVars(t *testing.T) {
	t.Parallel()
	got, err := renderString("subj", "Hello {{.name}}, vuln {{.cve}}",
		map[string]any{"name": "Ada", "cve": "CVE-2024-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "Hello Ada, vuln CVE-2024-0001" {
		t.Errorf("got %q", got)
	}
}

func TestRenderString_RejectsMalformedTemplate(t *testing.T) {
	t.Parallel()
	if _, err := renderString("body", "{{.unclosed", map[string]any{}); err == nil {
		t.Error("malformed template should error")
	}
}

func TestRenderString_MissingVarRendersZero(t *testing.T) {
	t.Parallel()
	// text/template renders missing keys as <no value> by default.
	got, _ := renderString("x", "v={{.absent}}", map[string]any{})
	if !strings.Contains(got, "<no value>") && got != "v=" {
		t.Errorf("missing var rendered as %q", got)
	}
}

func TestMemoryTransport_RecordsSentMessages(t *testing.T) {
	t.Parallel()
	mt := &MemoryTransport{}
	msg := Message{From: "x@y", To: []string{"a@b"}, Subject: "S"}
	if err := mt.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	sent := mt.Sent()
	if len(sent) != 1 || sent[0].Subject != "S" {
		t.Errorf("sent=%+v", sent)
	}
	// Second send appends, doesn't replace
	if err := mt.Send(context.Background(), Message{Subject: "S2"}); err != nil {
		t.Fatal(err)
	}
	if len(mt.Sent()) != 2 {
		t.Errorf("expected 2 messages, got %d", len(mt.Sent()))
	}
}

// FuzzRenderString — template source comes from operator config; vars
// from finding payloads (attacker-influenced). renderString must
// never panic regardless of input.
func FuzzRenderString(f *testing.F) {
	f.Add("Hello {{.x}}", "world")
	f.Add("", "")
	f.Add("{{.unclosed", "x")
	f.Add("{{range .x}}{{.}}{{end}}", "x")
	f.Add("{{.x.y.z}}", "")
	f.Fuzz(func(t *testing.T, src, val string) {
		_, _ = renderString("fuzz", src, map[string]any{"x": val})
	})
}
