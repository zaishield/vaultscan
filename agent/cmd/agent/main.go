// agent is the silent internal scanner that runs inside customer networks
// (Blueprint §6, §13). It only makes outbound TLS connections to the
// agent-gateway, only executes RSA-signed jobs, and only runs allow-listed
// tools, with cgroup-style CPU/memory enforcement and an emergency-stop
// listener.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/zaishield/vaultscan/agent/internal/cache"
	"github.com/zaishield/vaultscan/agent/internal/emergency"
	"github.com/zaishield/vaultscan/agent/internal/enroll"
	"github.com/zaishield/vaultscan/agent/internal/heartbeat"
	"github.com/zaishield/vaultscan/agent/internal/mtls"
	"github.com/zaishield/vaultscan/agent/internal/packager"
	"github.com/zaishield/vaultscan/agent/internal/policy"
	"github.com/zaishield/vaultscan/agent/internal/rotation"
	"github.com/zaishield/vaultscan/agent/internal/runner"
	"github.com/zaishield/vaultscan/agent/internal/updater"
	"github.com/zaishield/vaultscan/agent/internal/uploader"
	"github.com/zaishield/vaultscan/agent/internal/verifier"
)

// AgentVersion is the build-time agent version reported in heartbeats
// and used by the updater to compute whether an offered bundle is
// applicable. Override with `-ldflags "-X main.AgentVersion=x.y.z"`.
var AgentVersion = "1.0.0"

func main() {
	gateway := flag.String("gateway", os.Getenv("VAULTSCAN_GATEWAY"), "agent-gateway base URL")
	dataDir := flag.String("data-dir", "/var/lib/vaultscan-agent", "local cache directory")
	enrollToken := flag.String("enroll-token", "", "one-time enrollment token (first run)")
	agentIDStr := flag.String("agent-id", os.Getenv("VAULTSCAN_AGENT_ID"), "agent UUID")
	pollInterval := flag.Duration("poll", 10*time.Second, "job poll interval")
	hbInterval := flag.Duration("heartbeat", 30*time.Second, "heartbeat interval")
	flag.Parse()

	log := zerolog.New(os.Stderr).With().Timestamp().Str("component", "agent").Logger()
	if *gateway == "" {
		log.Fatal().Msg("--gateway is required")
	}

	agentID, err := uuid.Parse(*agentIDStr)
	if err != nil {
		log.Fatal().Err(err).Msg("agent-id must be a UUID")
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal().Err(err).Msg("create data dir")
	}
	cstore, err := cache.NewEncrypted(filepath.Join(*dataDir, "cache"))
	if err != nil {
		log.Fatal().Err(err).Msg("init encrypted cache")
	}

	localPolicy := policy.NewLocal()
	// HTTP client: mTLS-enabled when the gateway requires it (production),
	// plain TLS otherwise. Env-gated so a single-node compose can still run.
	client := &http.Client{Timeout: 60 * time.Second}
	if strings.ToLower(os.Getenv("VAULTSCAN_GATEWAY_MTLS")) == "on" {
		mClient, err := mtls.Client(*dataDir)
		if err != nil {
			log.Fatal().Err(err).Msg("mTLS client requested but cert/key missing — run enrollment first")
		}
		client = mClient
		log.Info().Msg("agent using mTLS client transport")
	}
	ag := &Agent{
		log:        log,
		gateway:    *gateway,
		agentID:    agentID,
		dataDir:    *dataDir,
		client:     client,
		cache:      cstore,
		policy:     localPolicy,
		runner:     runner.New().WithPolicy(localPolicy),
		packager:   packager.New(),
		uploader:   uploader.New(),
		verifier:   verifierWithEmbedded(),
		emergency:  emergency.New(),
		counters:   &heartbeat.Counters{},
	}

	if *enrollToken != "" {
		if err := enroll.Run(ag.client, *gateway, agentID, *enrollToken, *dataDir); err != nil {
			log.Fatal().Err(err).Msg("enrollment failed")
		}
		log.Info().Msg("enrollment succeeded")
	}

	fp, err := enroll.LoadFingerprint(*dataDir)
	if err != nil {
		log.Fatal().Err(err).Msg("agent has no certificate; run with --enroll-token")
	}
	ag.fingerprint = fp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First-boot bootstrap: if no cloud public key is on disk yet, pull it
	// from the API and cache it under data-dir/cloud-public.pem. Subsequent
	// boots find it via the standard search path.
	if !ag.verifier.Loaded() {
		if err := ag.verifier.FetchAndPersist(ctx, *gateway, *dataDir); err != nil {
			log.Warn().Err(err).
				Msg("cloud public key unavailable; agent will refuse every job until a key is provisioned")
		} else {
			log.Info().Msg("cloud public key fetched and cached")
		}
	}

	// Cert rotation goroutine — refreshes the cert within RotateBefore
	// of expiry, atomic on-disk swap, surfaces the new fingerprint to
	// the rest of the agent via a dynamic getter.
	ag.rotator = rotation.New(ag.client, *gateway, agentID, *dataDir, ag.fingerprint)
	ag.rotator.RotateBefore = 30 * 24 * time.Hour
	ag.rotator.CheckEvery = 12 * time.Hour

	// Signed update-bundle installer. Uses the same cloud public key that
	// verifies job signatures (loaded into ag.verifier).
	updaterInst := updater.New(ag.client, *gateway, agentID, *dataDir,
		ag.verifier.PublicKey(), AgentVersion)
	updaterInst.OnInstalled = func(target string) {
		log.Info().Str("bundle", target).
			Msg("update bundle installed; supervisor will restart the agent on next interval")
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		heartbeat.Run(ctx, log, heartbeat.Config{
			Gateway:        *gateway,
			AgentID:        agentID,
			Fingerprint:    ag.rotator.Fingerprint,
			ScannerVersion: AgentVersion,
			Every:          *hbInterval,
			Counters:       ag.counters,
			Emergency:      ag.emergency,
		})
	}()
	go func() {
		defer wg.Done()
		ag.runJobLoop(ctx, *pollInterval)
	}()
	go func() {
		defer wg.Done()
		ag.rotator.Run(ctx, func(newFp string) {
			ag.fingerprint = newFp
			// If we're talking mTLS, hot-swap the leaf cert in the
			// HTTP transport so subsequent requests use the new cert
			// without a process restart.
			if strings.ToLower(os.Getenv("VAULTSCAN_GATEWAY_MTLS")) == "on" {
				if err := mtls.UpdateClientCert(ag.client, *dataDir); err != nil {
					log.Warn().Err(err).Msg("hot-swap client cert failed")
				}
			}
			log.Info().Str("fingerprint", newFp[:16]+"…").Msg("cert rotated; new fingerprint live")
		})
	}()
	go func() {
		defer wg.Done()
		updaterInst.Run(ctx)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutdown")
	cancel()
	wg.Wait()
}

type Agent struct {
	log         zerolog.Logger
	gateway     string
	agentID     uuid.UUID
	fingerprint string
	dataDir     string
	client      *http.Client
	cache       *cache.Encrypted
	policy      *policy.Local
	runner      *runner.Runner
	packager    *packager.Packager
	uploader    *uploader.Uploader
	verifier    *verifier.Verifier
	emergency   *emergency.Listener
	counters    *heartbeat.Counters
	rotator     *rotation.Rotator
}

type job struct {
	ID            uuid.UUID  `json:"id"`
	PlatformID    uuid.UUID  `json:"platform_id"`
	PartnerID     uuid.UUID  `json:"partner_id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	EngagementID  uuid.UUID  `json:"engagement_id"`
	AgentID       *uuid.UUID `json:"agent_id"`
	ProfileCode   string     `json:"profile_code"`
	Plane         string     `json:"plane"`
	Tools         []string   `json:"tools"`
	Targets       []string   `json:"targets"`
	JobSignature  string     `json:"job_signature"`
	SigningKeyID  string     `json:"signing_key_id"`
}

func (a *Agent) runJobLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if a.emergency.Stopped() {
				continue
			}
			a.pollAndRun(ctx)
		}
	}
}

func (a *Agent) pollAndRun(ctx context.Context) {
	resp, err := a.do(ctx, http.MethodGet,
		fmt.Sprintf("/api/v1/agents/jobs/poll?max=%d", a.policy.MaxConcurrent()), nil)
	if err != nil {
		a.log.Warn().Err(err).Msg("poll")
		return
	}
	defer resp.Body.Close()
	var doc struct{ Items []job `json:"items"` }
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return
	}
	for _, j := range doc.Items {
		go a.execute(ctx, j)
	}
}

func (a *Agent) execute(ctx context.Context, j job) {
	a.log.Info().Str("job", j.ID.String()).Str("profile", j.ProfileCode).Msg("dispatching job")
	a.counters.BumpRunning(1)
	defer a.counters.BumpRunning(-1)

	// Verify the cloud-issued signature before doing anything.
	// Manifest shape MUST match scanorch.CanonicalManifest exactly —
	// any divergence between cloud and agent fails RSA verification.
	manifest, _ := json.Marshal(map[string]any{
		"agent_id":      j.AgentID,
		"engagement_id": j.EngagementID,
		"job_id":        j.ID,
		"plane":         j.Plane,
		"profile":       j.ProfileCode,
		"targets":       j.Targets,
		"tenant_id":     j.TenantID,
		"tools":         j.Tools,
	})
	if err := a.verifier.Verify(manifest, j.JobSignature, j.SigningKeyID); err != nil {
		a.log.Error().Err(err).Msg("rejecting unsigned/tampered job")
		_ = a.postStatus(ctx, j.ID, "failed", "signature verification failed")
		return
	}

	// Local policy enforcement - second line of defence behind ScopeGuard.
	if !a.policy.AllowsProfile(j.ProfileCode) {
		_ = a.postStatus(ctx, j.ID, "failed", "profile not permitted by local policy")
		return
	}
	for _, t := range j.Targets {
		if !a.policy.AllowsTarget(t) {
			_ = a.postStatus(ctx, j.ID, "failed", "target "+t+" not in local allowed scope")
			return
		}
	}

	_ = a.postStatus(ctx, j.ID, "running", "")

	tools := profileTools(j.ProfileCode)
	for _, tool := range tools {
		if a.emergency.Stopped() {
			_ = a.postStatus(ctx, j.ID, "killed", "emergency stop")
			return
		}
		out, err := a.runner.Execute(ctx, tool, j.Targets, a.policy.MaxCPUPercent(), a.policy.MaxMemoryPercent())
		if err != nil {
			a.log.Warn().Err(err).Str("tool", tool).Msg("tool failed")
			if errors.Is(err, runner.ErrToolNotAllowed) {
				a.counters.BumpImagePullsFailed()
			}
			// ErrSyntheticForbidden is structural: a production
			// agent has a missing binary that the cloud profile
			// expected. Fail the job and let ops investigate
			// rather than silently dropping the tool.
			if errors.Is(err, runner.ErrSyntheticForbidden) {
				_ = a.postStatus(ctx, j.ID, "failed",
					"tool binary missing on agent and synthetic forbidden: "+tool)
				return
			}
			continue
		}
		pkg, err := a.packager.Package(out)
		if err == nil {
			if err := a.uploader.UploadResult(ctx, a.client, a.gateway, j.ID, tool, pkg,
				a.agentID, a.fingerprint); err != nil {
				a.log.Warn().Err(err).Msg("upload failed")
			}
		}
	}

	_ = a.postStatus(ctx, j.ID, "succeeded", "")
}

func (a *Agent) postStatus(ctx context.Context, jobID uuid.UUID, state, errMsg string) error {
	body, _ := json.Marshal(map[string]string{"state": state, "error": errMsg})
	resp, err := a.do(ctx, http.MethodPost,
		"/api/v1/agents/jobs/"+jobID.String()+"/status", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (a *Agent) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	u, err := url.Parse(a.gateway + path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Id", a.agentID.String())
	req.Header.Set("X-Agent-Cert-Fingerprint", a.fingerprint)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(req)
}

// profileTools maps a scan profile code to the tool list. This shadows the
// cloud-side definition; the agent only runs allow-listed tools regardless.
func profileTools(code string) []string {
	switch code {
	case "internal_discovery":
		return []string{"nmap"}
	case "internal_standard_va":
		return []string{"nmap", "openvas", "nuclei"}
	case "internal_web_va":
		return []string{"zap", "nuclei"}
	case "internal_ad_review":
		return []string{"bloodhound", "netexec"}
	case "internal_linux_hardening":
		return []string{"lynis"}
	case "internal_k8s_review":
		return []string{"kube-bench", "kube-hunter", "trivy"}
	case "internal_container_review":
		return []string{"trivy"}
	default:
		return []string{"nmap"}
	}
}

// ldflags-populated build metadata.
//
//   version, commit, builtAt — populated by goreleaser via -X
//   embeddedCloudPubKeyB64   — populated from the
//                              VAULTSCAN_CLOUD_PUBLIC_KEY_B64 secret
//                              at release time. Base64-encoded PEM.
//
// Operators rotating the cloud signer re-build the agent (already
// required for crypto-agility) so the embedded key is replaced
// atomically with the binary.
var (
	version                  = "dev"
	commit                   = ""
	builtAt                  = ""
	embeddedCloudPubKeyB64   = ""
)

// verifierWithEmbedded constructs a verifier.Verifier and seeds it
// with the cloud public key embedded at build time. Falls back to
// the legacy /etc/vaultscan-agent/cloud-public.pem path + env-var
// flow if no key was embedded (dev builds).
func verifierWithEmbedded() *verifier.Verifier {
	v := verifier.New()
	if embeddedCloudPubKeyB64 == "" {
		return v
	}
	pemBytes, err := base64.StdEncoding.DecodeString(embeddedCloudPubKeyB64)
	if err != nil {
		return v
	}
	_ = v.LoadFromPEM(pemBytes)
	return v
}

// --- the following stub helpers keep imports referenced ------

var _ = exec.Command
var _ = sha256.Sum256
var _ = hex.EncodeToString
var _ = io.Copy
var _ = strings.HasSuffix
