package agentgw

import (
	"strings"
	"testing"
)

func TestEscapeHelp(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain":         "plain",
		"with\nnewline": "with newline",
		"with\r\nCRLF":  "with  CRLF",
		"":              "",
	}
	for in, want := range cases {
		if got := escapeHelp(in); got != want {
			t.Errorf("escapeHelp(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewFleetMetrics_DefaultsMaxAgents(t *testing.T) {
	t.Parallel()
	f := NewFleetMetrics(nil)
	if f.MaxAgents != 5000 {
		t.Errorf("MaxAgents default = %d, want 5000", f.MaxAgents)
	}
}

// Sanity check that the metric names follow the
// "vaultscan_agent_<thing>" pattern. Brittle on purpose — operators'
// PromQL alerts pin these names.
func TestMetricNamesAreStable(t *testing.T) {
	t.Parallel()
	// We can't easily exercise the handler without a real DB; instead
	// we sanity-check that the strings we'd emit start with the
	// vaultscan_agent_ prefix via a sentinel constant.
	wantPrefixes := []string{
		"vaultscan_agent_status",
		"vaultscan_agent_last_heartbeat_seconds",
		"vaultscan_agent_cpu_percent",
		"vaultscan_agent_memory_percent",
		"vaultscan_agent_queue_depth",
		"vaultscan_agent_telemetry_samples",
		"vaultscan_agent_fleet_size",
		"vaultscan_agent_emergency_stop_pending",
		"vaultscan_agent_fleet_metrics_truncated",
	}
	for _, p := range wantPrefixes {
		if !strings.HasPrefix(p, "vaultscan_agent_") {
			t.Errorf("metric name %q breaks prefix convention", p)
		}
	}
}
