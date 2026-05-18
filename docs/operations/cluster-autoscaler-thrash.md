# Runbook — cluster autoscaler thrash

## Symptom

Nodes are scaling up + scaling down in a tight loop. Customer
impact: intermittent 5xx during the down-scale window;
`scanner_tasks_running` oscillates.

## Initial triage

```bash
# Frequency of node add/remove events:
kubectl get events -n kube-system --field-selector reason=ScalingReplicaSet | wc -l
kubectl get events -A | grep -E "NodeNotReady|ScaleDown|TriggeredScaleUp"

# Per-deployment HPA state:
kubectl get hpa -n vaultscan

# Cluster-autoscaler logs (cloud-specific):
# AWS:   kubectl logs -n kube-system -l app=cluster-autoscaler
# GCP:   gcloud logging read 'resource.type=k8s_cluster'
# Azure: az aks show + check the autoscaler events on the VMSS
```

## Likely causes

| Symptom | Cause |
| --- | --- |
| Add node → immediate remove | HPA target utilisation too low (e.g. 30%); workload churns small |
| Add node → remove in <10 min | `scale-down-unneeded-time` too short; new pod hasn't bound yet |
| Scaling triggered by single overscheduled tool pod | A scanner Job with too-tight resource limits forces a new node |
| Oscillation across spot/on-demand | Spot preemption mid-scan; orchestrator immediately re-queues |

## Decision tree

### HPA target too aggressive

Check whether the API / agent-gateway HPA is set to a low utilisation
target:

```bash
kubectl get hpa -n vaultscan vaultscan-agent-gateway -o yaml | \
  grep -A2 targetCPUUtilizationPercentage
```

If <50%, raise to 60-70%. The chart default is 60%; sites that
lowered it for "safety" often induce thrash.

### Autoscaler scale-down too eager

Cloud-specific knob:
- AWS Karpenter: `consolidationPolicy: WhenUnderutilized` + `expireAfter`
- GKE Autopilot: managed; tickets-only adjust
- Azure VMSS: `scale-down-unneeded-time` + `scale-down-delay-after-add`

Raise `scale-down-delay-after-add` to >10 min so a freshly-added
node has time to be useful.

### Scanner-tool resource bloat

```bash
# Find which tools are demanding the most:
kubectl get pods -A -o json | jq -r \
  '.items[] | select(.metadata.labels."vaultscan.io/tool") |
   [.metadata.labels."vaultscan.io/tool",
    .spec.containers[0].resources.requests.cpu,
    .spec.containers[0].resources.requests.memory] | @tsv' | sort -u
```

If a tool is requesting > 2 cores / 4 GiB, audit whether it
actually needs that much. Tighten via `internal/scanner/runner_k8s.go`
`specForTool`.

## Immediate mitigation

```bash
# Lower-bound the scanner-worker so brief node-loss doesn't kill
# the dispatch loop:
kubectl scale -n vaultscan deployment/vaultscan-scanner-worker --replicas=3

# Pause the autoscaler temporarily on the offending node group:
# (cloud-specific). For Karpenter:
kubectl patch nodepool default --type=merge \
  -p '{"spec":{"disruption":{"consolidationPolicy":"WhenEmpty"}}}'

# Re-enable after the storm subsides + the underlying cause is fixed.
```

## Don'ts

- **Do NOT** pin the cluster to a minimum size that's permanently
  > 2x baseline. That defeats autoscaling and costs money.
- **Do NOT** disable HPAs to "stabilise." HPAs aren't the cause;
  the cause is bad sizing or bad scale-down config.
- **Do NOT** schedule scanner workloads on the same node pool as
  the API. Tail latency spikes during scan bursts.

## Postmortem questions

- Did we have node-pool-level metrics? If not, surface them.
- Was the cost of the thrash measurable? Add an alert at
  `cluster_autoscaler_nodes_count{state="scale_down"}` > N/hour.
- Can we use a separate node pool per workload class
  (api / worker / scanner)?

## Related

- `capacity-planning.md` (sizing model)
- `scanner-job-stuck-pending.md` (under-sizing symptom)
- `waf-rate-limit-storm.md` (a cause of sudden traffic-driven scale)
