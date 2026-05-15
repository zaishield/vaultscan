package packager

import (
	"testing"

	"github.com/zaishield/vaultscan/agent/internal/runner"
)

func TestPackager_PrefersStdout(t *testing.T) {
	p := New()
	out := &runner.Output{Stdout: []byte("stdout content"), Stderr: []byte("err")}
	got, err := p.Package(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "stdout content" {
		t.Errorf("got %q, want 'stdout content'", got)
	}
}

func TestPackager_FallsBackToStderr(t *testing.T) {
	p := New()
	got, _ := p.Package(&runner.Output{Stderr: []byte("err only")})
	if string(got) != "err only" {
		t.Errorf("got %q", got)
	}
}

func TestPackager_BothEmpty(t *testing.T) {
	p := New()
	got, err := p.Package(&runner.Output{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty bytes, got %d", len(got))
	}
}
