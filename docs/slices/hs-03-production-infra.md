# HS-03 · Production Infrastructure

Production reference architecture lives under `infra/` and matches the per-component
sizing from Blueprint §26.

| Component             | Spec (per node)                          | Source                                       |
|-----------------------|------------------------------------------|----------------------------------------------|
| Control plane         | 3 × 16 vCPU / 64 GB / 500 GB-1 TB NVMe  | `infra/k8s/control-plane/`                   |
| PostgreSQL HA         | 3 × 16-32 vCPU / 64-128 GB / 2-4 TB NVMe | `infra/helm/postgres-ha-values.yaml`         |
| Object storage (Ceph) | 3-5 nodes / 16 vCPU / 64 GB / 20 TB+    | `infra/k8s/storage/ceph-cluster.yaml`        |
| OpenSearch            | 3 × 16 vCPU / 64 GB / 2-4 TB NVMe        | `infra/helm/opensearch-values.yaml`          |
| Scanner farm (small)  | 3 × 32 vCPU / 64-128 GB / 2-4 TB NVMe    | `infra/k8s/scanner-farm/`                    |
| Agent gateway         | Dedicated subnet, port 443 only          | `infra/k8s/agent-gateway/`                   |

## Network segments (Blueprint §27.1)

`public-ingress`, `application`, `database`, `storage`, `scanner`, `agent-gateway`,
`monitoring`, `backup` — all defined as Kubernetes NetworkPolicies under
`infra/k8s/network-policies/`.

## Static scanner IPs (Blueprint §5.5)

The `scanner_node_registry` seed (migration `0010`) registers 5 regional pools
with reverse DNS and `abuse@zaishield.com`. Production deployments map the
hostnames to LoadBalancer Services with annotation
`service.beta.kubernetes.io/aws-load-balancer-eip-allocations`.

For local development the same shape runs in `infra/compose/docker-compose.yml`.
