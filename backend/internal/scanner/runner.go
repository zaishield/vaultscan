package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/envmode"
)

// Runner executes a scanner tool. The production runner is a Kubernetes Job
// in a regional scanner-* namespace with strict NetworkPolicy + ResourceQuota
// (Blueprint §12). The dev runner shells out to the host's binary if
// installed and otherwise — IF allowed — returns a synthetic payload so the
// rest of the pipeline can be exercised end-to-end without every tool present.
//
// Production guard: when AllowSynthetic is false, a missing host binary
// returns ErrSyntheticForbidden instead of fabricated output. The default
// is determined by VAULTSCAN_ENV at construction time:
//
//   VAULTSCAN_ENV=production | prod  → AllowSynthetic = false
//   anything else (or unset)         → AllowSynthetic = true
//
// Tests can construct NewRunnerForTest() to opt in explicitly.
type Runner struct {
	// AllowSynthetic decides whether a missing host binary triggers
	// fabricated output. Production must keep this false to avoid
	// fabricated findings entering the data plane. Default value is
	// driven by NewRunner() — see file-level comment.
	AllowSynthetic bool
}

// ErrSyntheticForbidden is returned when AllowSynthetic is false and
// the host binary is not on PATH. The worker treats this as a hard
// failure for the scan task — better to mark the task failed than to
// ingest fake findings into the data plane.
var ErrSyntheticForbidden = errors.New("scanner: host binary not found and synthetic output disabled")

// NewRunner returns a runner whose AllowSynthetic flag is set according
// to VAULTSCAN_ENV. Production deployments boot with synthetics OFF.
func NewRunner() *Runner {
	return &Runner{AllowSynthetic: !envmode.FromEnv()}
}

// NewRunnerForTest returns a runner that always allows synthetic output.
// Use this from test harnesses that intentionally exercise the parser
// pipeline without real binaries.
func NewRunnerForTest() *Runner {
	return &Runner{AllowSynthetic: true}
}

// NewRunnerStrict returns a runner that always refuses synthetic output.
// Use this from environments that should fail loudly when binaries are
// missing — staging, CI smoke against real images.
func NewRunnerStrict() *Runner {
	return &Runner{AllowSynthetic: false}
}

// Result is what the runner returns for one tool invocation.
type Result struct {
	Tool       string
	Output     []byte
	ExitCode   int
	Took       time.Duration
	Synthetic  bool // true when the host binary wasn't found and a stub was emitted
}

// Run executes `tool` against the given targets with a runtime cap. Any
// process that exceeds the runtime cap is killed by ctx cancellation.
//
// imageRef is ignored — LocalRunner exec's against the host's $PATH
// rather than a container image. Present in the signature only to
// satisfy the ExecRunner interface (the K8s runner uses it).
func (r Runner) Run(ctx context.Context, imageRef, tool string, targets []string, runtime time.Duration) (*Result, error) {
	_ = imageRef
	if runtime <= 0 {
		runtime = 30 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, runtime)
	defer cancel()

	args := buildArgs(tool, targets)
	bin, lookupErr := exec.LookPath(tool)
	if lookupErr != nil {
		if !r.AllowSynthetic {
			return nil, fmt.Errorf("%w: tool=%s", ErrSyntheticForbidden, tool)
		}
		return &Result{
			Tool:       tool,
			Output:     []byte(synth(tool, targets)),
			Synthetic:  true,
			ExitCode:   0,
		}, nil
	}

	start := time.Now()
	cmd := exec.CommandContext(cctx, bin, args...)
	// Cap stdout/stderr at 64 MiB so a runaway tool can't OOM the
	// worker. The cap matches the K8s runner's pod-log cap. Real
	// scanner output is well under 64 MiB; anything larger is
	// either misconfiguration or hostile.
	const maxOutput = 64 << 20
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("scanner: stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("scanner: stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("scanner: start %s: %w", tool, err)
	}
	out, _ := io.ReadAll(io.LimitReader(stdoutPipe, maxOutput))
	errBytes, _ := io.ReadAll(io.LimitReader(stderrPipe, maxOutput))
	err = cmd.Wait()
	took := time.Since(start)
	res := &Result{Tool: tool, Output: out, Took: took}
	if err != nil {
		var exitErr *exec.ExitError
		if errAs(err, &exitErr) {
			res.Output = append(res.Output, errBytes...)
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("scanner: run %s: %w", tool, err)
	}
	return res, nil
}

// errAs is a small generic wrapper around errors.As to keep the call site tight.
func errAs[T error](err error, target *T) bool {
	if err == nil {
		return false
	}
	// stdlib errors.As pattern but inline so we don't need to import here
	// (avoids an extra dep tree at the call site).
	for e := err; e != nil; e = unwrap(e) {
		if t, ok := e.(T); ok {
			*target = t
			return true
		}
	}
	return false
}

func unwrap(err error) error {
	type wrapped interface{ Unwrap() error }
	if w, ok := err.(wrapped); ok {
		return w.Unwrap()
	}
	return nil
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
	case "openvas":
		return targets
	case "prowler":
		return []string{"aws", "--output-format", "json-ocsf"}
	default:
		return targets
	}
}

// synth produces minimal valid output for parsers when the host doesn't have
// the binary installed. Keeps the dev pipeline running end-to-end.
//
// NEVER called when AllowSynthetic=false. Production deployments get
// ErrSyntheticForbidden up the stack instead.
func synth(tool string, targets []string) string {
	t := firstOr(targets, "127.0.0.1")
	switch tool {
	case "nmap":
		return `<?xml version="1.0"?><nmaprun><host><address addr="` + t + `" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18"/></port></ports></host></nmaprun>`
	case "nuclei":
		return `{"template-id":"http-missing-security-headers","info":{"name":"Missing security headers","severity":"low"},"host":"` +
			t + `","matched-at":"` + t + `"}`
	case "lynis":
		return "warning[]=PKGS-7392|System has accounts with weak password policy|\n"
	case "testssl":
		return `[{"id":"cipherlist_TLSv1_0","ip":"` + t + `","port":"443","severity":"medium","finding":"Legacy TLS 1.0 enabled"}]`
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
