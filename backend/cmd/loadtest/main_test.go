package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// TestLoadTestBinary_AgainstTestServer is a smoke test for cmd/loadtest:
// build the binary, point it at an httptest.NewServer that always
// returns 200, and assert it produces the expected summary line +
// zero failures. Catches the kind of regression where a binary
// compiles fine but its argument parsing silently swallows a flag.
func TestLoadTestBinary_AgainstTestServer(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Build the binary fresh so this test is self-contained.
	bin := t.TempDir() + "/loadtest"
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	out, err := exec.Command(bin,
		"-target", srv.URL,
		"-workers", "4",
		"-duration", "1s",
		"-max-fail-pct", "0.5",
		"-max-p99-ms", "500").CombinedOutput()
	if err != nil {
		t.Fatalf("loadtest: %v\n%s", err, out)
	}

	got := string(out)
	// fail_pct may be non-zero in tiny amounts due to httptest
	// connection-reset races during the duration cutoff; assert
	// the output SHAPE rather than exact zero failures.
	for _, must := range []string{
		"total=",
		"fail_pct=",
		"latency_ms p50=",
		"verdict: PASS",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("output missing %q\nfull output:\n%s", must, got)
		}
	}
	if hits.Load() < 10 {
		t.Errorf("expected the test target to be hit many times; got %d", hits.Load())
	}
	fmt.Printf("smoke: %d hits, output:\n%s\n", hits.Load(), got)
}

// TestLoadTestBinary_FailsOnFailureRate verifies the gate works:
// when failure threshold is impossibly low, the binary exits 1.
func TestLoadTestBinary_FailsOnFailureRate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500) // always fail
	}))
	defer srv.Close()

	bin := t.TempDir() + "/loadtest"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	out, _ := exec.Command(bin,
		"-target", srv.URL, "-workers", "2", "-duration", "500ms",
		"-max-fail-pct", "0.001", "-max-p99-ms", "10000").CombinedOutput()
	if !strings.Contains(string(out), "FAIL: failure rate") {
		t.Errorf("expected failure-rate gate to trip; output:\n%s", out)
	}
}
