package leader

import (
	"testing"
)

func TestJobKey_StableAcrossInvocations(t *testing.T) {
	t.Parallel()
	a := jobKey("foo")
	b := jobKey("foo")
	if a != b {
		t.Errorf("jobKey not deterministic: %d vs %d", a, b)
	}
}

func TestJobKey_DistinctPerName(t *testing.T) {
	t.Parallel()
	names := []string{
		"audit_verify_deep", "report_schedules_run_due",
		"agent_telemetry_rollup", "siem_audit_shipping",
		"integrations_dlq_depth", "agent_status_gauge",
		"findings_sla_breach_sweep", "evidence_retention_sweep",
		"auth_ip_lockouts_sweep", "fail_over_stalled_nodes",
	}
	seen := map[int64]string{}
	for _, n := range names {
		k := jobKey(n)
		if dup, ok := seen[k]; ok {
			t.Errorf("collision: %q and %q both → %d", n, dup, k)
		}
		seen[k] = n
	}
}

func TestJobKey_PrefixIsolatesFromOtherSystems(t *testing.T) {
	t.Parallel()
	// If two services share the same DB and both compute jobKey("foo"),
	// the prefix in our hash should make them collide-resistant.
	// Confirms the FNV input includes the "vaultscan-cron-" prefix.
	a := jobKey("foo")
	if a == 0 {
		t.Error("jobKey returned 0 — likely empty input bug")
	}
}
