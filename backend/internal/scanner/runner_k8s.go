// runner_k8s.go — Kubernetes Job-based scanner runner.
//
// Implements Blueprint §12.1–§12.2: each tool execution is a fresh
// batch/v1 Job in scanner-<region> namespace with:
//   * runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities
//   * tight CPU/memory requests + limits
//   * activeDeadlineSeconds matching the per-task runtime cap
//   * backoffLimit=0 (failures don't auto-retry; the orchestrator
//     decides whether to re-dispatch)
//   * NetworkPolicy applied at the namespace level by the operator
//     (chart ships sample manifests)
//
// Why not client-go: that dependency is ~30MB of transitive code +
// codegen machinery. The K8s REST API is just HTTP+JSON, and we
// already speak that fluently (cloud-posture adapters use the same
// pattern). Result: this file is ~250 lines + zero new deps.
//
// In-cluster auth:
//   token  = read once from /var/run/secrets/kubernetes.io/serviceaccount/token
//   ca     = /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
//   apiURL = https://kubernetes.default.svc
//
// All k8s API calls send Authorization: Bearer <token> and validate
// the API server against the SA-provided CA.

package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultK8sAPI    = "https://kubernetes.default.svc"
	saTokenPath      = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath         = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath  = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	apiBatchV1       = "/apis/batch/v1/namespaces/%s/jobs"
	apiBatchV1Job    = "/apis/batch/v1/namespaces/%s/jobs/%s"
	apiCoreV1Pods    = "/api/v1/namespaces/%s/pods"
	apiCoreV1PodLog  = "/api/v1/namespaces/%s/pods/%s/log"
)

// K8sJobConfig holds the per-process configuration: namespace, region,
// image registry. Each Run() invocation spawns one Job.
type K8sJobConfig struct {
	APIServer     string  // override for tests; production reads kubernetes.default.svc
	Namespace     string  // default: scanner-<region> if region set, else "scanner"
	Region        string
	ImageRegistry string  // e.g. registry.zaishield.com/vaultscan/scanners
	// HTTPClient is overridable for tests; production builds one from
	// the in-cluster CA + bearer token.
	HTTPClient *http.Client
	// ServiceAccount under which the Job's Pod runs. Defaults to
	// "scanner-tool" — the chart's RBAC binds this SA with the minimum
	// it needs (none — tool pods don't touch the K8s API).
	ServiceAccount string
	// AllowSynthetic flag — propagated by the wrapper layer for parity
	// with LocalRunner. K8s mode never emits synthetic output; the
	// flag exists for the interface contract.
	AllowSynthetic bool
}

// K8sJobRunner implements ExecRunner via the Kubernetes batch/v1 API.
type K8sJobRunner struct {
	cfg        K8sJobConfig
	tokenMu    sync.RWMutex
	token      string
	tokenReadAt time.Time
	apiBase    string
	httpClient *http.Client
}

// saTokenRefreshInterval bounds how stale the cached SA token can
// be. Modern K8s projected SA tokens rotate every ~1h (bounded SA
// tokens, projected tokens with expirationSeconds=3600). Without a
// refresh path the runner starts returning 401 after the first hour
// and scan jobs silently fail to dispatch.
const saTokenRefreshInterval = 10 * time.Minute

// NewK8sJobRunner reads the in-cluster SA token + CA on construction.
// Fails fast if either is missing — production deployments MUST run
// inside a Pod with a ServiceAccount token mounted.
func NewK8sJobRunner(cfg K8sJobConfig) (*K8sJobRunner, error) {
	if cfg.Namespace == "" {
		if cfg.Region != "" {
			cfg.Namespace = "scanner-" + cfg.Region
		} else if ns, err := os.ReadFile(saNamespacePath); err == nil {
			cfg.Namespace = strings.TrimSpace(string(ns))
		} else {
			cfg.Namespace = "scanner"
		}
	}
	if cfg.ServiceAccount == "" {
		cfg.ServiceAccount = "scanner-tool"
	}
	if cfg.ImageRegistry == "" {
		cfg.ImageRegistry = "registry.zaishield.com/vaultscan/scanners"
	}
	apiBase := cfg.APIServer
	if apiBase == "" {
		apiBase = defaultK8sAPI
	}

	tokenBytes, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: read SA token: %w", err)
	}

	hc := cfg.HTTPClient
	if hc == nil {
		caBytes, err := os.ReadFile(saCAPath)
		if err != nil {
			return nil, fmt.Errorf("k8s: read SA CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, errors.New("k8s: SA CA PEM invalid")
		}
		hc = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
		}
	}

	return &K8sJobRunner{
		cfg:        cfg,
		token:      strings.TrimSpace(string(tokenBytes)),
		tokenReadAt: time.Now(),
		apiBase:    apiBase,
		httpClient: hc,
	}, nil
}

// refreshSATokenIfStale re-reads the SA token from disk when the
// cached value is older than saTokenRefreshInterval. K8s projected
// tokens rotate ~hourly; the kubelet refreshes the on-disk file
// transparently. Without this poll the runner kept using its
// boot-time token until the API rejected with 401.
func (r *K8sJobRunner) refreshSATokenIfStale() {
	r.tokenMu.RLock()
	// Skip refresh entirely when the runner was constructed without
	// going through NewK8sJobRunner (tests that inject a stub token
	// directly leave tokenReadAt zero). The production path sets it.
	if r.tokenReadAt.IsZero() {
		r.tokenMu.RUnlock()
		return
	}
	stale := time.Since(r.tokenReadAt) > saTokenRefreshInterval
	r.tokenMu.RUnlock()
	if !stale {
		return
	}
	r.tokenMu.Lock()
	defer r.tokenMu.Unlock()
	// Re-check under the write lock to avoid a thundering-herd re-read.
	if time.Since(r.tokenReadAt) <= saTokenRefreshInterval {
		return
	}
	tokenBytes, err := os.ReadFile(saTokenPath)
	if err != nil {
		// Keep using the cached token; the next request will retry.
		// (A persistent failure surfaces as 401 from the API server.)
		return
	}
	r.token = strings.TrimSpace(string(tokenBytes))
	r.tokenReadAt = time.Now()
}

func (r *K8sJobRunner) SetAllowSynthetic(b bool) { r.cfg.AllowSynthetic = b }

// Run creates a Job, waits for completion, harvests the pod log, and
// returns the bytes as Result.Output. The Job is deleted on
// completion (success or failure) to keep the namespace clean.
//
// Timing: Run blocks until the Job hits a terminal state OR ctx is
// cancelled OR `runtime` elapses. The Job carries activeDeadlineSeconds
// matching `runtime` so the kubelet kills the pod even if we crash.
//
// `imageRef` MUST be the verified-by-cosign reference (typically
// "<registry>/<tool>@sha256:<digest>") that the caller's
// Registry.VerifyImage step approved. Pulling :latest here would
// defeat the entire supply-chain gate — admission ran on a SHA the
// signer attested, but K8s would then pull whatever :latest pointed
// to at run time. The cosign gate is meaningless if the runtime
// reference differs from what was signed.
func (r *K8sJobRunner) Run(ctx context.Context, imageRef, tool string, targets []string, runtime time.Duration) (*Result, error) {
	if runtime <= 0 {
		runtime = 30 * time.Minute
	}
	if imageRef == "" {
		return nil, fmt.Errorf("k8s: imageRef required (caller must pass the cosign-verified ref)")
	}
	jobName := jobNameFor(tool)
	manifest := buildJobManifest(jobName, r.cfg.Namespace, r.cfg.ServiceAccount,
		imageRef, tool, buildArgs(tool, targets), runtime)

	start := time.Now()

	// 1. Create the Job.
	if err := r.createJob(ctx, manifest); err != nil {
		return nil, fmt.Errorf("k8s: create job %s: %w", jobName, err)
	}
	// Always delete on the way out — production runs thousands of jobs
	// per region; without cleanup the namespace fills up.
	defer func() {
		delCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.deleteJob(delCtx, jobName)
	}()

	// 2. Wait for terminal status. We poll status every 2s; the Job's
	// activeDeadlineSeconds bounds the worst case from the kubelet.
	exitCode, err := r.waitForCompletion(ctx, jobName, runtime+30*time.Second)
	if err != nil {
		return nil, err
	}

	// 3. Find the Job's Pod + harvest logs. The kubelet may garbage-
	// collect a completed pod aggressively, so be tolerant of "pod
	// terminated" 400s — return what we have rather than failing the
	// whole job (the exit code is the authoritative outcome).
	podName, err := r.podForJob(ctx, jobName)
	if err != nil {
		return &Result{Tool: tool, ExitCode: exitCode, Took: time.Since(start)}, nil
	}
	output, err := r.podLogs(ctx, podName)
	if err != nil {
		// Pod was already cleaned up by the kubelet — return the exit
		// code without logs rather than failing the whole job.
		return &Result{Tool: tool, ExitCode: exitCode, Took: time.Since(start)}, nil
	}

	return &Result{
		Tool:     tool,
		Output:   output,
		ExitCode: exitCode,
		Took:     time.Since(start),
	}, nil
}

// jobNameFor builds a DNS-1123-safe name: vs-<tool>-<short uuid>.
// Job names are namespace-scoped and 63 chars max; we cap at 50 to
// leave room for K8s-appended pod hashes.
func jobNameFor(tool string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == '-':
			return r
		}
		return -1
	}, tool)
	if safe == "" {
		safe = "tool"
	}
	short := strings.ReplaceAll(uuid.New().String(), "-", "")[:8]
	n := "vs-" + safe + "-" + short
	if len(n) > 50 {
		n = n[:50]
	}
	return n
}

// buildJobManifest is a hand-built JSON blob matching the batch/v1
// Job schema. We don't use client-go's structs; the schema is small
// enough that a map[string]any is clearer.
func buildJobManifest(name, namespace, sa, image, tool string, args []string, runtime time.Duration) []byte {
	deadline := int64(runtime / time.Second)
	if deadline < 60 {
		deadline = 60
	}
	manifest := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels": map[string]any{
				"app.kubernetes.io/name":       "vaultscan-scanner",
				"app.kubernetes.io/component":  "scanner-tool",
				"app.kubernetes.io/managed-by": "scanner-worker",
				"vaultscan.io/tool":            tool,
			},
		},
		"spec": map[string]any{
			"backoffLimit":          0,
			"activeDeadlineSeconds": deadline,
			"ttlSecondsAfterFinished": 60, // GC if our defer-delete races
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						"app.kubernetes.io/name":      "vaultscan-scanner",
						"app.kubernetes.io/component": "scanner-tool",
						"vaultscan.io/tool":           tool,
					},
				},
				"spec": specForTool(tool, sa, image, args),
			},
		},
	}
	body, _ := json.Marshal(manifest)
	return body
}

// ---- low-level k8s REST ---------------------------------------------------

func (r *K8sJobRunner) createJob(ctx context.Context, manifest []byte) error {
	url := r.apiBase + fmt.Sprintf(apiBatchV1, r.cfg.Namespace)
	resp, body, err := r.doJSON(ctx, http.MethodPost, url, manifest)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("k8s POST jobs: %d %s", resp.StatusCode, body)
	}
	return nil
}

func (r *K8sJobRunner) deleteJob(ctx context.Context, name string) error {
	url := r.apiBase + fmt.Sprintf(apiBatchV1Job, r.cfg.Namespace, name)
	// propagationPolicy=Background so pods are GC'd async.
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		url+"?propagationPolicy=Background", nil)
	r.setAuth(req)
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// waitForCompletion polls Job status until succeeded/failed/timeout.
// Returns the container exit code (0 on success, non-zero on failure).
func (r *K8sJobRunner) waitForCompletion(ctx context.Context, name string, deadline time.Duration) (int, error) {
	deadlineT := time.Now().Add(deadline)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	url := r.apiBase + fmt.Sprintf(apiBatchV1Job, r.cfg.Namespace, name)
	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-tick.C:
		}
		if time.Now().After(deadlineT) {
			return -1, fmt.Errorf("k8s: job %s exceeded poll deadline %s", name, deadline)
		}
		resp, body, err := r.doJSON(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		var j struct {
			Status struct {
				Succeeded int   `json:"succeeded"`
				Failed    int   `json:"failed"`
				Active    int   `json:"active"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		}
		if err := json.Unmarshal(body, &j); err != nil {
			continue
		}
		if j.Status.Succeeded > 0 {
			return 0, nil
		}
		if j.Status.Failed > 0 {
			return 1, nil
		}
		for _, c := range j.Status.Conditions {
			if (c.Type == "Failed" || c.Type == "FailureTarget") && c.Status == "True" {
				return 1, nil
			}
		}
	}
}

func (r *K8sJobRunner) podForJob(ctx context.Context, jobName string) (string, error) {
	url := r.apiBase +
		fmt.Sprintf(apiCoreV1Pods, r.cfg.Namespace) +
		"?labelSelector=job-name=" + jobName
	resp, body, err := r.doJSON(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("k8s GET pods: %d %s", resp.StatusCode, body)
	}
	var l struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &l); err != nil {
		return "", err
	}
	if len(l.Items) == 0 {
		return "", errors.New("no pod found for job")
	}
	return l.Items[0].Metadata.Name, nil
}

func (r *K8sJobRunner) podLogs(ctx context.Context, podName string) ([]byte, error) {
	url := r.apiBase + fmt.Sprintf(apiCoreV1PodLog, r.cfg.Namespace, podName)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	r.setAuth(req)
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("k8s GET pod/log: %d %s", resp.StatusCode, body)
	}
	// Cap log read at 64 MiB — runaway logs shouldn't OOM the worker.
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func (r *K8sJobRunner) doJSON(ctx context.Context, method, url string, body []byte) (*http.Response, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, nil, err
	}
	r.setAuth(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp, out, err
}

func (r *K8sJobRunner) setAuth(req *http.Request) {
	r.refreshSATokenIfStale()
	r.tokenMu.RLock()
	req.Header.Set("Authorization", "Bearer "+r.token)
	r.tokenMu.RUnlock()
}
