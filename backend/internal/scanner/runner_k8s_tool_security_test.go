package scanner

import (
	"encoding/json"
	"testing"
)

// Strict default: a tool not in any override map gets the locked-
// down pod + container security context.
func TestSecurityContext_StrictDefault(t *testing.T) {
	pod := podSecurityContextForTool("nuclei")
	if pod["runAsNonRoot"] != true {
		t.Errorf("strict-default pod: runAsNonRoot != true, got %v", pod["runAsNonRoot"])
	}
	if pod["runAsUser"] != 65532 {
		t.Errorf("strict-default pod: runAsUser != 65532")
	}
	c := containerSecurityContextForTool("nuclei")
	if c["runAsNonRoot"] != true {
		t.Errorf("strict-default container: runAsNonRoot != true")
	}
	caps, ok := c["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities missing")
	}
	drop, _ := caps["drop"].([]string)
	if len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("expected drop=[ALL], got %v", drop)
	}
	if _, has := caps["add"]; has {
		t.Errorf("strict-default must not add capabilities, got %v", caps["add"])
	}
}

// kube-bench needs root + hostNetwork + hostPID; runAsNonRoot must
// be relaxed at BOTH pod and container scope.
func TestSecurityContext_KubeBenchRoot(t *testing.T) {
	pod := podSecurityContextForTool("kube-bench")
	if _, has := pod["runAsNonRoot"]; has {
		t.Errorf("kube-bench pod must NOT set runAsNonRoot (was: %v)", pod["runAsNonRoot"])
	}
	c := containerSecurityContextForTool("kube-bench")
	if c["runAsNonRoot"] != false {
		t.Errorf("kube-bench container: runAsNonRoot != false")
	}
	if !toolNeedsHostNetwork("kube-bench") {
		t.Error("kube-bench needs hostNetwork")
	}
	if !toolNeedsHostPID("kube-bench") {
		t.Error("kube-bench needs hostPID")
	}
}

// lynis needs root but NOT hostNetwork / hostPID.
func TestSecurityContext_LynisRootNoHost(t *testing.T) {
	c := containerSecurityContextForTool("lynis")
	if c["runAsNonRoot"] != false {
		t.Errorf("lynis container: runAsNonRoot != false")
	}
	if toolNeedsHostNetwork("lynis") {
		t.Error("lynis MUST NOT use hostNetwork (host-audit scope, not network)")
	}
	if toolNeedsHostPID("lynis") {
		t.Error("lynis MUST NOT use hostPID")
	}
}

// OpenVAS: non-root + NET_RAW added.
func TestSecurityContext_OpenVASCaps(t *testing.T) {
	pod := podSecurityContextForTool("openvas")
	if pod["runAsNonRoot"] != true {
		t.Errorf("openvas pod: runAsNonRoot != true")
	}
	c := containerSecurityContextForTool("openvas")
	caps := c["capabilities"].(map[string]any)
	add, _ := caps["add"].([]string)
	hasNetRaw := false
	for _, c := range add {
		if c == "NET_RAW" {
			hasNetRaw = true
		}
	}
	if !hasNetRaw {
		t.Errorf("openvas must add NET_RAW, got %v", add)
	}
}

// nmap + naabu also need NET_RAW for SYN/UDP scans but stay non-root.
func TestSecurityContext_NetRawScanners(t *testing.T) {
	for _, tool := range []string{"nmap", "naabu"} {
		c := containerSecurityContextForTool(tool)
		if c["runAsNonRoot"] != true {
			t.Errorf("%s: runAsNonRoot != true", tool)
		}
		caps := c["capabilities"].(map[string]any)
		add, _ := caps["add"].([]string)
		if len(add) == 0 || add[0] != "NET_RAW" {
			t.Errorf("%s: expected NET_RAW in capability adds, got %v", tool, add)
		}
	}
}

// Manifest end-to-end: kube-bench dispatches with the elevations.
func TestBuildJobManifest_KubeBenchHostScope(t *testing.T) {
	raw := buildJobManifest("test-job", "ns", "sa", "reg/kube-bench:1.0",
		"kube-bench", []string{"--targets", "master"}, 60_000_000_000)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest not valid JSON: %v", err)
	}
	tpl := m["spec"].(map[string]any)["template"].(map[string]any)
	podSpec := tpl["spec"].(map[string]any)
	if podSpec["hostNetwork"] != true {
		t.Errorf("kube-bench manifest must have hostNetwork=true")
	}
	if podSpec["hostPID"] != true {
		t.Errorf("kube-bench manifest must have hostPID=true")
	}
}

// Default tool produces a manifest with hostNetwork=false / hostPID=false.
func TestBuildJobManifest_DefaultNoHostScope(t *testing.T) {
	raw := buildJobManifest("t", "ns", "sa", "reg/nuclei:1.0",
		"nuclei", []string{"-target", "x"}, 60_000_000_000)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	podSpec := m["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if podSpec["hostNetwork"] != false {
		t.Errorf("nuclei manifest must have hostNetwork=false, got %v", podSpec["hostNetwork"])
	}
	if podSpec["hostPID"] != false {
		t.Errorf("nuclei manifest must have hostPID=false, got %v", podSpec["hostPID"])
	}
}
