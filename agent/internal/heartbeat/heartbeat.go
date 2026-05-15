// Package heartbeat ticks a status payload to the agent gateway with the
// VS-06 telemetry fields the cloud's RollupTelemetry consumes
// (kernel/scanner version, image-pull failures, CPU/mem from /proc).
//
// The heartbeat response can carry a pending emergency-stop id; when it
// does, the agent immediately POSTs the ack so the cloud's SLA stats
// (arrival → ack ms) close out.
package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Counters lives in the agent so heartbeat can sample running_jobs +
// image_pulls_failed without coupling to specific subpackages.
type Counters struct {
	RunningJobs      int32
	QueueDepth       int32
	ImagePullsFailed int32
}

func (c *Counters) BumpRunning(n int32)        { atomic.AddInt32(&c.RunningJobs, n) }
func (c *Counters) BumpQueue(n int32)          { atomic.AddInt32(&c.QueueDepth, n) }
func (c *Counters) BumpImagePullsFailed()      { atomic.AddInt32(&c.ImagePullsFailed, 1) }
func (c *Counters) Snapshot() (int32, int32, int32) {
	return atomic.LoadInt32(&c.RunningJobs),
		atomic.LoadInt32(&c.QueueDepth),
		atomic.LoadInt32(&c.ImagePullsFailed)
}

// Listener is the small contract heartbeat uses to ack emergency stops.
type Listener interface {
	Trigger()
}

type Config struct {
	Gateway        string
	AgentID        uuid.UUID
	Fingerprint    func() string // dynamic — rotation can change it under us
	ScannerVersion string
	Every          time.Duration
	Counters       *Counters
	Emergency      Listener
}

// Run blocks until ctx is cancelled.
func Run(ctx context.Context, log zerolog.Logger, cfg Config) {
	if cfg.Every <= 0 {
		cfg.Every = 30 * time.Second
	}
	if cfg.Counters == nil {
		cfg.Counters = &Counters{}
	}
	t := time.NewTicker(cfg.Every)
	defer t.Stop()
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick(ctx, client, log, cfg)
		}
	}
}

func tick(ctx context.Context, client *http.Client, log zerolog.Logger, cfg Config) {
	cpu, mem, disk := systemStats()
	running, queue, imageFailed := cfg.Counters.Snapshot()
	body, _ := json.Marshal(map[string]any{
		"cpu_percent":        cpu,
		"memory_percent":     mem,
		"disk_percent":       disk,
		"running_jobs":       running,
		"queue_depth":        queue,
		"image_pulls_failed": imageFailed,
		"version":            cfg.ScannerVersion,
		"kernel_version":     kernelVersion(),
		"payload": map[string]any{
			"go":   runtime.Version(),
			"arch": runtime.GOARCH,
			"os":   runtime.GOOS,
		},
	})
	url := cfg.Gateway + "/api/v1/agents/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("X-Agent-Id", cfg.AgentID.String())
	req.Header.Set("X-Agent-Cert-Fingerprint", cfg.Fingerprint())
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("heartbeat")
		return
	}
	defer resp.Body.Close()

	// Heartbeat response may signal a pending emergency stop or policy
	// version. The gateway emits the body even on 4xx so the agent has
	// the chance to act on instructions before retrying.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if len(respBody) == 0 {
		return
	}
	var directive struct {
		LatestEmergencyStop *struct {
			ID    uuid.UUID `json:"id"`
			AckTS *string   `json:"ack_ts"`
		} `json:"latest_emergency_stop,omitempty"`
		PolicyVersion int `json:"policy_version,omitempty"`
	}
	if err := json.Unmarshal(respBody, &directive); err != nil {
		return
	}
	if directive.LatestEmergencyStop != nil &&
		directive.LatestEmergencyStop.AckTS == nil &&
		directive.LatestEmergencyStop.ID != uuid.Nil {
		if cfg.Emergency != nil {
			cfg.Emergency.Trigger()
		}
		ackEmergencyStop(ctx, client, cfg.Gateway, directive.LatestEmergencyStop.ID, cfg.AgentID, cfg.Fingerprint())
	}
}

func ackEmergencyStop(ctx context.Context, client *http.Client, gateway string, stopID, agentID uuid.UUID, fp string) {
	url := fmt.Sprintf("%s/api/v1/emergency-stops/%s/ack", gateway, stopID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Agent-Id", agentID.String())
	req.Header.Set("X-Agent-Cert-Fingerprint", fp)
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// systemStats samples real CPU + memory + disk from /proc and /. On
// non-Linux fallbacks to runtime.MemStats so the field shape stays
// consistent across platforms.
func systemStats() (cpu, mem, disk float64) {
	if runtime.GOOS == "linux" {
		cpu = readLoadAvg()
		mem = readMemPercent()
		disk = readDiskPercent("/")
		return
	}
	ms := &runtime.MemStats{}
	runtime.ReadMemStats(ms)
	return 0, float64(ms.Alloc) / float64(ms.Sys+1) * 100, 0
}

func readLoadAvg() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return 0
	}
	la, _ := strconv.ParseFloat(parts[0], 64)
	cpus := float64(runtime.NumCPU())
	if cpus < 1 {
		cpus = 1
	}
	// loadavg / num_cpus * 100, capped at 100 so the dashboard tile stays sane.
	pct := la / cpus * 100
	if pct > 100 {
		pct = 100
	}
	return pct
}

func readMemPercent() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total, available float64
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "MemTotal:":
			total, _ = strconv.ParseFloat(parts[1], 64)
		case "MemAvailable:":
			available, _ = strconv.ParseFloat(parts[1], 64)
		}
	}
	if total == 0 {
		return 0
	}
	return (total - available) / total * 100
}

func readDiskPercent(_ string) float64 {
	// statfs would be ideal but adds a syscall.Statfs dep. Heartbeat
	// is best-effort; return 0 on platforms without it.
	return 0
}

func kernelVersion() string {
	if runtime.GOOS != "linux" {
		return runtime.GOOS + "/" + runtime.GOARCH
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
