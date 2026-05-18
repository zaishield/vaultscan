# Runbook — scanner Job stuck pending

## Symptom

`vaultscan_scan_tasks_queued` is rising but `vaultscan_scan_tasks_running`
isn't. Or: a customer reports "started a scan 15 min ago, no
results." `kubectl get jobs -n scanner-<tool>` shows Jobs in
`Pending` state.

## Initial triage

```bash
# Find the stuck Jobs.
for ns in $(kubectl get ns -o jsonpath='{.items[?(@.metadata.name=~"scanner-.*")].metadata.name}'); do
  kubectl get jobs -n "$ns" --field-selector=status.successful=0,status.failed=0
done

# For ONE such Job, get the events.
kubectl describe job -n scanner-nuclei vaultscan-scan-abc123
kubectl get events -n scanner-nuclei --sort-by='.lastTimestamp' | tail -20
```

## Decision tree

| Event message | Cause | Fix |
| --- | --- | --- |
| `Insufficient cpu/memory` | Cluster under-provisioned | Scale node group; review tool resource limits |
| `ImagePullBackOff` | Registry creds; image not signed; digest not in `digests.json` | Verify `tools/scanner-images/digests.json`; check Kyverno policy |
| `Forbidden: violates PodSecurity` | Tool's PodSecurityContext violates the namespace's policy | Add tool to `runner_k8s_tool_security.go` overrides |
| `failed to set up sandbox container` | CNI / containerd issue | Drain + reboot the node; check the kubelet log |
| `0/N nodes are available: untolerated taint` | Wrong nodeSelector / no taint toleration | Check scanner-worker dispatch labels match a node pool |
| `error creating: namespaces "scanner-X" not found` | Per-tool namespace missing | Apply `infra/helm/vaultscan/templates/scanner-namespaces.yaml` |

## Immediate mitigation

### Pull-blocked

```bash
# Confirm the image is signed + in digests.json.
jq -r '.digests."nuclei"' tools/scanner-images/digests.json

# If empty, the strict-mode orchestrator will REFUSE to dispatch
# (intentional). Either populate via a v* tag release, or set
# VAULTSCAN_REQUIRE_PINNED_IMAGES=false on the api Deployment
# (NOT recommended in production).
```

### Resource-blocked

```bash
# Burst the node pool. Cloud-specific:
# AWS:    eksctl scale nodegroup --cluster=X --name=Y --nodes=N
# GCP:    gcloud container clusters resize X --node-pool Y --num-nodes N
# Azure:  az aks scale --resource-group X --name Y --node-count N
# kind:   add another worker node + kind start

# Also check whether the scanner-worker is dispatching to the
# RIGHT node pool (some clouds have a "spot" pool that can be
# preempted mid-scan).
```

### Quota-blocked

If a tenant has hit its per-tenant scan quota, the orchestrator
queues but never dispatches. Surface via:

```bash
curl -s "$API/api/v1/scanner/regions/$REGION/quota" \
  -H "Authorization: Bearer $ADMIN_JWT" | jq
```

Either raise the tenant's quota or wait for the rolling window.

## Don'ts

- **Do NOT** force-delete the Job (`--grace-period=0 --force`). If
  the tool was about to start, the orphaned pod can hold a lease
  in the scan_tasks table.
- **Do NOT** dispatch the same scan manually via `kubectl create
  job ... --from=cronjob/...`. The orchestrator tracks state in
  `scan_tasks` — a manual job won't update the row + the original
  will eventually retry.

## Postmortem questions

- Why didn't the alert `VaultScanScanQueueDepthHigh` fire earlier?
- Was the cluster's autoscaler too slow? (See `cluster-autoscaler-thrash.md`)
- Should we add a per-tool `kubectl get jobs` dashboard panel?

## Related

- `scanner-and-agent-plane-production.md` (architecture)
- `cluster-autoscaler-thrash.md`
- `scanner-image-release.md`
