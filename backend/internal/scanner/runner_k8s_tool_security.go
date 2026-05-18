// runner_k8s_tool_security.go — per-tool pod-security overrides.
//
// Most scanner tools work fine under the strict default (uid 65532,
// readOnlyRootFilesystem, drop ALL caps, runAsNonRoot=true). A small
// number of host-audit and raw-socket tools need elevations that
// the strict default refuses; without per-tool overrides their pods
// fail to schedule or produce empty results.
//
// Tools with documented elevations (matching the Dockerfile comments
// under tools/scanner-images/<tool>/):
//
//   kube-bench  — must run as root to read /etc/kubernetes + the
//                 kubelet config; needs hostNetwork + hostPID to
//                 cover all CIS Kubernetes Benchmark checks.
//   lynis       — host-audit; needs root to read /etc/shadow,
//                 /proc, secure logs. NO hostPID/hostNetwork.
//   openvas     — raw-socket port scans; needs NET_RAW + NET_BIND_
//                 SERVICE. Runs as non-root with those caps.
//
// Adding a new tool: extend the maps below + update the matching
// Dockerfile comment + this file's test.

package scanner

// podSecurityContextForTool returns the Pod-level securityContext
// for `tool`. Defaults to the strict non-root profile; tools listed
// in `rootPodTools` get an empty securityContext (no runAsNonRoot
// enforcement at pod level, container-level still has its own).
func podSecurityContextForTool(tool string) map[string]any {
	if rootPodTools[tool] {
		// No pod-level runAsNonRoot for host-audit tools. seccomp
		// stays RuntimeDefault for consistency.
		return map[string]any{
			"seccompProfile": map[string]any{"type": "RuntimeDefault"},
		}
	}
	return map[string]any{
		"runAsNonRoot":   true,
		"runAsUser":      65532,
		"runAsGroup":     65532,
		"fsGroup":        65532,
		"seccompProfile": map[string]any{"type": "RuntimeDefault"},
	}
}

// containerSecurityContextForTool returns the per-container
// securityContext. Strict default drops ALL caps. Per-tool overrides
// add capabilities back or relax runAsNonRoot.
func containerSecurityContextForTool(tool string) map[string]any {
	base := map[string]any{
		"allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem":   true,
		"capabilities":             map[string]any{"drop": []string{"ALL"}},
	}
	if rootContainerTools[tool] {
		base["runAsNonRoot"] = false
		// host-audit tools don't read a writable rootfs — but the
		// underlying image often does (creates /tmp working dirs);
		// keep readOnlyRootFilesystem true and rely on the /tmp
		// emptyDir mount.
	} else {
		base["runAsNonRoot"] = true
	}
	if caps, ok := toolCapabilityAdds[tool]; ok {
		base["capabilities"] = map[string]any{
			"drop": []string{"ALL"},
			"add":  caps,
		}
	}
	return base
}

// toolNeedsHostNetwork returns true when the tool requires
// hostNetwork. Only kube-bench currently does (cluster-wide
// CIS-Benchmark coverage).
func toolNeedsHostNetwork(tool string) bool { return hostNetworkTools[tool] }

// toolNeedsHostPID returns true for tools that need to see host
// processes (kube-bench checks /proc/<pid> of the kubelet, etcd, etc.).
func toolNeedsHostPID(tool string) bool { return hostPIDTools[tool] }

// specForTool assembles the full pod-template-spec for `tool`. Kept
// in this file (not the manifest builder) so the per-tool toggles
// stay co-located.
func specForTool(tool, sa, image string, args []string) map[string]any {
	return map[string]any{
		"restartPolicy":                "Never",
		"serviceAccountName":           sa,
		"automountServiceAccountToken": false,
		"hostNetwork":                  toolNeedsHostNetwork(tool),
		"hostPID":                      toolNeedsHostPID(tool),
		"securityContext":              podSecurityContextForTool(tool),
		"containers": []any{
			map[string]any{
				"name":            tool,
				"image":           image,
				"args":            args,
				"securityContext": containerSecurityContextForTool(tool),
				"resources": map[string]any{
					"requests": map[string]any{"cpu": "200m", "memory": "256Mi"},
					"limits":   map[string]any{"cpu": "2", "memory": "4Gi"},
				},
				"volumeMounts": []any{
					map[string]any{"name": "tmp", "mountPath": "/tmp"},
				},
			},
		},
		"volumes": []any{
			map[string]any{"name": "tmp", "emptyDir": map[string]any{"sizeLimit": "1Gi"}},
		},
	}
}

// rootPodTools = pod-level runAsNonRoot is relaxed.
var rootPodTools = map[string]bool{
	"kube-bench": true,
	"lynis":      true,
}

// rootContainerTools = container-level runAsNonRoot is relaxed.
// kube-bench + lynis are host-audit tools that genuinely need uid 0;
// openvas does NOT — it runs as non-root with NET_RAW added.
var rootContainerTools = map[string]bool{
	"kube-bench": true,
	"lynis":      true,
}

// toolCapabilityAdds = capabilities granted back after the default
// drop ALL. Default drop ALL stays in effect; these are added on top.
var toolCapabilityAdds = map[string][]string{
	// OpenVAS performs ICMP + raw-socket port scans. Without
	// NET_RAW, scans fall back to TCP-connect-only which misses
	// every UDP service. NET_BIND_SERVICE lets it bind <1024 if
	// the user explicitly requests it.
	"openvas": {"NET_RAW", "NET_BIND_SERVICE"},
	// nmap also supports raw scans; the upstream image runs as
	// uid 10001 + drops privs after binding the socket, but
	// NET_RAW is needed for -sS (SYN) and -sU (UDP).
	"nmap": {"NET_RAW", "NET_BIND_SERVICE"},
	// naabu = SYN scan by default.
	"naabu": {"NET_RAW", "NET_BIND_SERVICE"},
}

// hostNetworkTools = pod uses hostNetwork. Only kube-bench needs
// this; it inspects node-local network state.
var hostNetworkTools = map[string]bool{
	"kube-bench": true,
}

// hostPIDTools = pod sees host processes. kube-bench checks
// kubelet / etcd / kube-apiserver processes via /proc.
var hostPIDTools = map[string]bool{
	"kube-bench": true,
}
