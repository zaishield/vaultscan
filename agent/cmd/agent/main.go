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
	"encoding/hex"
	"encoding/json"
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
	"github.com/zaishield/vaultscan/agent/internal/packager"
	"github.com/zaishield/vaultscan/agent/internal/policy"
	"github.com/zaishield/vaultscan/agent/internal/runner"
	"github.com/zaishield/vaultscan/agent/internal/uploader"
	"github.com/zaishield/vaultscan/agent/internal/verifier"
)

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

	ag := &Agent{
		log:        log,
		gateway:    *gateway,
		agentID:    agentID,
		dataDir:    *dataDir,
		client:     &http.Client{Timeout: 60 * time.Second},
		cache:      cstore,
		policy:     policy.NewLocal(),
		runner:     runner.New(),
		packager:   packager.New(),
		uploader:   uploader.New(),
		verifier:   verifier.New(),
		emergency:  emergency.New(),
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		heartbeat.Run(ctx, log, *gateway, agentID, ag.fingerprint, *hbInterval)
	}()
	go func() {
		defer wg.Done()
		ag.runJobLoop(ctx, *pollInterval)
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
}

type job struct {
	ID            uuid.UUID `json:"id"`
	PlatformID    uuid.UUID `json:"platform_id"`
	PartnerID     uuid.UUID `json:"partner_id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	EngagementID  uuid.UUID `json:"engagement_id"`
	ProfileCode   string    `json:"profile_code"`
	Plane         string    `json:"plane"`
	Targets       []string  `json:"targets"`
	JobSignature  string    `json:"job_signature"`
	SigningKeyID  string    `json:"signing_key_id"`
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

	// Verify the cloud-issued signature before doing anything.
	manifest, _ := json.Marshal(map[string]any{
		"job_id": j.ID, "tenant_id": j.TenantID, "engagement_id": j.EngagementID,
		"profile": j.ProfileCode, "targets": j.Targets, "plane": j.Plane,
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

// --- the following stub helpers keep imports referenced ------

var _ = exec.Command
var _ = sha256.Sum256
var _ = hex.EncodeToString
var _ = io.Copy
var _ = strings.HasSuffix
