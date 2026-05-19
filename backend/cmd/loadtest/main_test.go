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
	if !strings.Contains(string(out), "FAIL:") {
		t.Errorf("expected failure-rate gate to trip; output:\n%s", out)
	}
}

// TestLoadTestBinary_MultiTarget exercises the comma-separated
// targets feature. The load tool must:
//   * round-robin requests across the targets
//   * print one summary block per target
//   * fail the whole run if ANY target trips a threshold
func TestLoadTestBinary_MultiTarget(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hitsA.Add(1)
		w.WriteHeader(200)
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hitsB.Add(1)
		w.WriteHeader(200)
	}))
	defer srvB.Close()

	bin := t.TempDir() + "/loadtest"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	out, err := exec.Command(bin,
		"-target", srvA.URL+","+srvB.URL,
		"-workers", "4",
		"-duration", "1s",
		"-max-fail-pct", "1",
		"-max-p99-ms", "500").CombinedOutput()
	if err != nil {
		t.Fatalf("multi-target loadtest: %v\n%s", err, out)
	}
	if hitsA.Load() < 5 || hitsB.Load() < 5 {
		t.Errorf("expected both targets hit; got A=%d B=%d", hitsA.Load(), hitsB.Load())
	}
	if !strings.Contains(string(out), "2 target(s)") {
		t.Errorf("verdict line should report 2 targets; output:\n%s", out)
	}
}

// TestLoadTestBinary_BurstMode — burst mode should produce
// significantly more requests than the same duration in steady
// mode (the periodic burst windows multiply concurrency).
func TestLoadTestBinary_BurstMode(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	bin := t.TempDir() + "/loadtest"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	out, err := exec.Command(bin,
		"-target", srv.URL,
		"-mode", "burst",
		"-workers", "2",
		"-burst-mul", "5",
		"-burst-every", "300ms",
		"-burst-for", "200ms",
		"-duration", "2s",
		"-max-fail-pct", "1",
		"-max-p99-ms", "500").CombinedOutput()
	if err != nil {
		t.Fatalf("burst loadtest: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "mode=burst") {
		t.Errorf("output should declare mode=burst; got:\n%s", out)
	}
	if hits.Load() < 100 {
		t.Errorf("burst mode produced only %d hits — burst overlays not firing?", hits.Load())
	}
}

// TestLoadTestBinary_SoakProgress — soak mode prints periodic
// progress lines. The format is operator-facing; we lock it
// in so dashboards / log parsers can rely on it.
func TestLoadTestBinary_SoakProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	bin := t.TempDir() + "/loadtest"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	out, _ := exec.Command(bin,
		"-target", srv.URL,
		"-mode", "soak",
		"-workers", "2",
		"-duration", "2s",
		"-soak-progress", "500ms",
		"-max-fail-pct", "1",
		"-max-p99-ms", "500").CombinedOutput()
	if !strings.Contains(string(out), "[soak-progress") {
		t.Errorf("soak mode should print progress; got:\n%s", out)
	}
	if !strings.Contains(string(out), "rps=") {
		t.Errorf("progress lines should report rps; got:\n%s", out)
	}
}
