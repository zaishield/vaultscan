// runner_interface.go — pluggable Runner contract. The original
// LocalRunner (exec.CommandContext to PATH) lives next to a real
// Kubernetes-Job-based runner that submits per-tool Jobs into
// dedicated scanner-* namespaces with NetworkPolicy + ResourceQuota
// per Blueprint §12.1–§12.2.
//
// Selection:
//   VAULTSCAN_SCANNER_RUNNER=local  (default) → LocalRunner
//   VAULTSCAN_SCANNER_RUNNER=k8s              → K8sJobRunner
//
// Production deployments running inside Kubernetes set
// VAULTSCAN_SCANNER_RUNNER=k8s so each tool runs in a fresh sandboxed
// container, isolated from sibling tools.

package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// ExecRunner is the contract both LocalRunner + K8sJobRunner satisfy.
//
// `imageRef` is the cosign-verified image reference (typically
// "<registry>/<tool>@sha256:<digest>") the caller's Registry.VerifyImage
// step approved. LocalRunner ignores it (exec'd against the host's
// $PATH, no image involved). K8sJobRunner USES it verbatim to ensure
// the supply-chain gate's verdict is what actually runs — pulling
// :latest at runtime would defeat the entire signature check.
type ExecRunner interface {
	Run(ctx context.Context, imageRef, tool string, targets []string, runtime time.Duration) (*Result, error)
	SetAllowSynthetic(bool)
	AllowsSynthetic() bool
}

// LocalRunner is the previous (and only) implementation: exec.Command
// against the host's PATH. Renamed from Runner to disambiguate from
// the new K8sJobRunner. The existing Runner type is kept as an alias
// for backwards compatibility (other packages reference it directly).
type LocalRunner = Runner

func (r *Runner) SetAllowSynthetic(b bool) { r.AllowSynthetic = b }
func (r *Runner) AllowsSynthetic() bool    { return r.AllowSynthetic }

// AllowsSynthetic on K8sJobRunner is always false in practice — Pods
// don't run host binaries; if the image is missing, the kubelet's
// image-pull failure is the surfaced error, not fabricated output.
// The flag is kept for interface parity + tests.
func (r *K8sJobRunner) AllowsSynthetic() bool { return r.cfg.AllowSynthetic }

// NewRunnerFromEnv reads VAULTSCAN_SCANNER_RUNNER and returns the
// appropriate ExecRunner. Defaults to LocalRunner for back-compat.
//
// k8s mode requires:
//   * a service-account token at /var/run/secrets/kubernetes.io/serviceaccount/token
//   * a CA cert at  /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
//   * VAULTSCAN_SCANNER_NAMESPACE  (default: scanner-<region>)
//   * VAULTSCAN_SCANNER_IMAGE_REGISTRY
//   * VAULTSCAN_SCANNER_REGION
//
// The pod's ServiceAccount needs RBAC: get/create/delete on
// batch.Jobs + get on pods + get on pods/log in the namespace.
// The Helm chart ships this RoleBinding (scanner-worker-rbac.yaml).
func NewRunnerFromEnv() (ExecRunner, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("VAULTSCAN_SCANNER_RUNNER")))
	switch mode {
	case "", "local":
		return NewRunner(), nil
	case "k8s", "kubernetes":
		k, err := NewK8sJobRunner(K8sJobConfig{
			Namespace:     os.Getenv("VAULTSCAN_SCANNER_NAMESPACE"),
			Region:        os.Getenv("VAULTSCAN_SCANNER_REGION"),
			ImageRegistry: os.Getenv("VAULTSCAN_SCANNER_IMAGE_REGISTRY"),
		})
		if err != nil {
			return nil, fmt.Errorf("scanner: init k8s runner: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("scanner: unknown VAULTSCAN_SCANNER_RUNNER=%q (want: local|k8s)", mode)
	}
}

// mustRunnerFromEnv calls NewRunnerFromEnv; on k8s-mode failure (e.g.
// SA token missing because the binary's running outside Kubernetes
// while VAULTSCAN_SCANNER_RUNNER=k8s), logs a warning and falls back
// to LocalRunner so the worker still boots in dev environments. In
// production VAULTSCAN_SCANNER_RUNNER should be set correctly + this
// fallback never trips.
func mustRunnerFromEnv(log zerolog.Logger) ExecRunner {
	r, err := NewRunnerFromEnv()
	if err != nil {
		log.Warn().Err(err).Msg("scanner runner init failed; falling back to LocalRunner")
		return NewRunner()
	}
	return r
}
