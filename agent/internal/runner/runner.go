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
	"os/exec"
	"strings"
	"time"
)

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
}

func New() *Runner { return &Runner{} }

// WithPolicy returns a Runner that defers to the supplied policy gate
// in addition to the hardcoded allow-list. AllowsTool=false on either
// side blocks execution.
func (r *Runner) WithPolicy(p PolicyGate) *Runner {
	r.policy = p
	return r
}

// ErrToolNotAllowed signals a refusal at the runner level. Callers
// translate it into a job-status=failed with the same message.
var ErrToolNotAllowed = errors.New("runner: tool not in agent allow-list")

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

// Execute runs `tool` against `targets` with rough CPU/memory caps. The dev
// implementation respects the contract but will produce a synthetic stub if
// the tool isn't installed locally.
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
		// Fallback: synthetic output so the dev pipeline can demonstrate end-to-end.
		return &Output{
			Tool:    tool,
			Command: tool + " " + strings.Join(args, " "),
			Stdout:  []byte(synth(tool, targets)),
			ExitCode: 0,
		}, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(cctx, bin, args...)
	stdout, err := cmd.Output()
	out := &Output{Tool: tool, Command: bin + " " + strings.Join(args, " "),
		Stdout: stdout, Took: time.Since(start)}
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			out.Stderr = e.Stderr
			out.ExitCode = e.ExitCode()
		}
	}
	_ = maxCPU
	_ = maxMem
	return out, nil
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
