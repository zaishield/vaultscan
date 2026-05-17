// Package runner is the local tool execution sandbox (Blueprint §13.3).
// In production this launches container-runtime jobs (docker/podman) with
// CPU/memory limits and an emergency-stop hook. The dev build executes the
// host binary if available; otherwise it returns a synthetic record so the
// rest of the upload pipeline can be exercised end-to-end.
//
// Hardening (HS-01 collaboration): the runner only ever exec()s binaries
// from a hardcoded allow-list. Even if a misconfigured local policy claims
// to allow `bash`, the runner refuses.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// isProductionEnv mirrors backend/internal/envmode.IsProduction for the
// runner's synthetic-output gate. Kept local rather than importing the
// backend pkg because the agent binary is a separate go.mod with no
// dependency on the backend module.
func isProductionEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("VAULTSCAN_ENV")))
	return v == "production" || v == "prod"
}

// allowedTools is the immutable allow-list. Adding a tool here is a
// deliberate code change; the agent will refuse to run anything else
// regardless of what the cloud policy says.
var allowedTools = map[string]bool{
	"nmap": true, "nuclei": true, "zap": true, "openvas": true,
	"testssl": true, "sslyze": true, "trivy": true, "lynis": true,
	"bloodhound": true, "netexec": true, "prowler": true,
	"kube-bench": true, "kube-hunter": true,
	"amass": true, "subfinder": true, "dnsx": true, "httpx": true,
	"naabu": true, "ffuf": true, "katana": true, "mobsf": true,
}

// PolicyGate is the tiny contract the runner needs to consult before
// exec. Both policy.Local and a stub implement it.
type PolicyGate interface {
	AllowsTool(tool string) bool
}

type Runner struct {
	policy PolicyGate
	// AllowSynthetic flag mirrors backend/internal/scanner.Runner.
	// false → if the host binary is missing, return ErrSyntheticForbidden
	// rather than fabricated output. Production agents MUST set this
	// to false; otherwise an attacker who hides nmap from the agent's
	// PATH could inject fake findings into the data plane.
	AllowSynthetic bool
}

// NewRunner returns a runner whose AllowSynthetic flag is set per env.
// Production agents (VAULTSCAN_ENV=production) refuse to fabricate
// scanner output; dev defaults to allowing synthetic so demos work
// without every tool installed.
func New() *Runner { return &Runner{AllowSynthetic: !isProductionEnv()} }

// NewRunnerStrict refuses synthetic output unconditionally. Use from
// staging or CI smoke tests that should fail loudly if a tool is
// missing.
func NewRunnerStrict() *Runner { return &Runner{AllowSynthetic: false} }

// WithPolicy returns a Runner that defers to the supplied policy gate
// in addition to the hardcoded allow-list. AllowsTool=false on either
// side blocks execution.
func (r *Runner) WithPolicy(p PolicyGate) *Runner {
	r.policy = p
	return r
}

// AllowsSynthetic surfaces the current flag so callers (the agent
// shell) can refuse to ingest synthetic output even if upstream
// somehow forwards it.
func (r *Runner) AllowsSynthetic() bool { return r.AllowSynthetic }

// ErrToolNotAllowed signals a refusal at the runner level. Callers
// translate it into a job-status=failed with the same message.
var ErrToolNotAllowed = errors.New("runner: tool not in agent allow-list")

// ErrSyntheticForbidden is returned when AllowSynthetic is false AND
// the host binary cannot be found in PATH. The agent treats this as a
// hard job failure to avoid silently injecting fabricated findings.
var ErrSyntheticForbidden = errors.New("runner: host binary missing and synthetic output forbidden")

// Output is the raw payload (typically tool stdout/stderr or the artifact
// path the tool writes to).
type Output struct {
	Tool     string
	Command  string
	Stdout   []byte
	Stderr   []byte
	Took     time.Duration
	ExitCode int
}

// Execute runs `tool` against `targets` with rough CPU/memory caps.
//
// Resource caps:
//   - maxCPU is interpreted as a wall-clock cap in seconds. The
//     context inherits a tighter deadline so a tool that goes
//     runaway is killed by CommandContext. 0 means use the default
//     30-minute cap.
//   - maxMem is interpreted as a soft cap in MiB. A watchdog
//     goroutine polls /proc/<pid>/status on Linux every 2s and
//     sends SIGKILL to the process group if RSS exceeds the cap.
//     On non-Linux platforms the watchdog is a no-op and ops should
//     enforce limits via cgroups / systemd-run wrapping the agent
//     binary. The previous version of this code did `_ = maxCPU;
//     _ = maxMem`, silently discarding policy limits.
func (r *Runner) Execute(ctx context.Context, tool string, targets []string, maxCPU, maxMem int) (*Output, error) {
	if !allowedTools[tool] {
		return nil, fmt.Errorf("%w: %q", ErrToolNotAllowed, tool)
	}
	if r.policy != nil && !r.policy.AllowsTool(tool) {
		return nil, fmt.Errorf("%w: %q (denied by policy)", ErrToolNotAllowed, tool)
	}
	args := buildArgs(tool, targets)
	bin := tool
	if path, err := exec.LookPath(tool); err == nil {
		bin = path
	} else {
		if !r.AllowSynthetic {
			return nil, fmt.Errorf("%w: tool=%s", ErrSyntheticForbidden, tool)
		}
		return &Output{
			Tool:    tool,
			Command: tool + " " + strings.Join(args, " "),
			Stdout:  []byte(synth(tool, targets)),
			ExitCode: 0,
		}, nil
	}
	wallCap := 30 * time.Minute
	if maxCPU > 0 {
		wallCap = time.Duration(maxCPU) * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, wallCap)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(cctx, bin, args...)
	// Put the child in its own process group so the watchdog can
	// SIGKILL the entire tree (nuclei / nmap fork helpers).
	cmd.SysProcAttr = newProcAttr()
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrBuf := &outputBuffer{}
	cmd.Stderr = stderrBuf
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("runner: start %s: %w", tool, err)
	}
	if maxMem > 0 {
		go watchMem(cctx, cmd.Process.Pid, maxMem)
	}
	stdout, _ := io.ReadAll(stdoutPipe)
	waitErr := cmd.Wait()
	out := &Output{
		Tool:    tool,
		Command: bin + " " + strings.Join(args, " "),
		Stdout:  stdout,
		Stderr:  stderrBuf.Bytes(),
		Took:    time.Since(start),
	}
	if waitErr != nil {
		if e, ok := waitErr.(*exec.ExitError); ok {
			out.ExitCode = e.ExitCode()
		} else {
			out.ExitCode = -1
		}
	}
	return out, nil
}

// outputBuffer is a tiny goroutine-safe byte sink used in place of
// cmd.Output()'s implicit buffering so we can read stderr after Wait.
type outputBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}
func (b *outputBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

func buildArgs(tool string, targets []string) []string {
	switch tool {
	case "nmap":
		return append([]string{"-sV", "-Pn", "-oX", "-"}, targets...)
	case "nuclei":
		return append([]string{"-jsonl", "-silent", "-u"}, strings.Join(targets, ","))
	case "zap":
		return append([]string{"-quickurl"}, strings.Join(targets, ","))
	case "trivy":
		return append([]string{"image", "--format", "json"}, targets...)
	case "kube-bench":
		return []string{"--json"}
	case "lynis":
		return []string{"audit", "system"}
	case "testssl":
		return append([]string{"--jsonfile-pretty", "-"}, targets...)
	case "sslyze":
		return append([]string{"--json_out=-"}, targets...)
	case "bloodhound":
		return targets
	case "netexec":
		return targets
	case "openvas":
		return targets
	case "prowler":
		return []string{"aws", "--output-format", "json-ocsf"}
	default:
		return targets
	}
}

func synth(tool string, targets []string) string {
	switch tool {
	case "nmap":
		return fmt.Sprintf(`<?xml version="1.0"?>
<nmaprun>
  <host><address addr="%s" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18"/></port>
    </ports>
  </host>
</nmaprun>`, firstOr(targets, "127.0.0.1"))
	case "nuclei":
		return `{"template-id":"http-missing-security-headers","info":{"name":"Missing security headers","severity":"low"},"host":"` +
			firstOr(targets, "https://example.com") + `","matched-at":"` +
			firstOr(targets, "https://example.com") + `"}`
	case "lynis":
		return "warning[]=PKGS-7392|System has accounts with weak password policy|\nsuggestion[]=KRNL-5820|Consider tuning kernel sysctl|\n"
	case "testssl":
		return `[{"id":"cipherlist_TLSv1_0","ip":"` + firstOr(targets, "127.0.0.1") +
			`","port":"443","severity":"medium","finding":"Legacy TLS 1.0 enabled","cve":"","cwe":""}]`
	default:
		return "synthetic placeholder for " + tool
	}
}

func firstOr(xs []string, def string) string {
	if len(xs) == 0 {
		return def
	}
	return xs[0]
}
