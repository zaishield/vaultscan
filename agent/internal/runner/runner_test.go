package runner

import (
	"context"
	"errors"
	"testing"
)

type allowAllPolicy struct{}

func (allowAllPolicy) AllowsTool(string) bool { return true }

type denyAllPolicy struct{}

func (denyAllPolicy) AllowsTool(string) bool { return false }

func TestExecute_RejectsToolNotInAllowList(t *testing.T) {
	r := New()
	_, err := r.Execute(context.Background(), "bash", []string{"127.0.0.1"}, 70, 75)
	if !errors.Is(err, ErrToolNotAllowed) {
		t.Fatalf("expected ErrToolNotAllowed for bash, got %v", err)
	}
	_, err = r.Execute(context.Background(), "rm", []string{"-rf"}, 70, 75)
	if !errors.Is(err, ErrToolNotAllowed) {
		t.Fatalf("expected ErrToolNotAllowed for rm, got %v", err)
	}
}

func TestExecute_AllowsListedTool(t *testing.T) {
	r := New()
	// nmap is on the allow-list; runner falls back to synthetic output
	// because the binary isn't installed in the test environment.
	out, err := r.Execute(context.Background(), "nmap", []string{"127.0.0.1"}, 70, 75)
	if err != nil {
		t.Fatalf("nmap (allow-listed) should not error: %v", err)
	}
	if out == nil || len(out.Stdout) == 0 {
		t.Fatal("nmap call returned empty output")
	}
}

func TestExecute_PolicyCanFurtherDeny(t *testing.T) {
	r := New().WithPolicy(denyAllPolicy{})
	// nmap is on the hardcoded allow-list but the policy denies it.
	_, err := r.Execute(context.Background(), "nmap", []string{"127.0.0.1"}, 70, 75)
	if !errors.Is(err, ErrToolNotAllowed) {
		t.Fatalf("policy-denied tool must surface ErrToolNotAllowed, got %v", err)
	}
}

func TestExecute_PolicyAllowDoesNotBypassAllowList(t *testing.T) {
	r := New().WithPolicy(allowAllPolicy{})
	_, err := r.Execute(context.Background(), "bash", []string{"127.0.0.1"}, 70, 75)
	if !errors.Is(err, ErrToolNotAllowed) {
		t.Fatal("policy=allow-all must NOT defeat the hardcoded allow-list")
	}
}
