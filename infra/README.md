# `infra/` layout

This directory holds every piece of deployment infrastructure for
VaultScan that lives outside the application code itself.

```
infra/
├── compose/          dev stack (docker-compose; not for staging+ use)
├── helm/             Helm chart — the ONLY supported production path
│   └── vaultscan/
│       ├── values.yaml            baseline (production-shaped)
│       ├── values-dev.yaml        single-replica overlay
│       ├── values-staging.yaml    2-replica + letsencrypt-staging
│       ├── values-uat.yaml        2-replica + Kyverno enforce
│       ├── values-prod.yaml       3-replica + every gate on
│       ├── values.kind.yaml       kind-cluster CI overlay
│       ├── templates/             deployment / service / ingress / RBAC / etc.
│       └── kind-cluster.yaml      kind config used by deploy-verify.sh
├── images/           images that are NOT the application binary
│   └── restore-verify/    alpine + pg_restore + awscli for the DR drill
├── keycloak/         realm-import JSON used by the compose stack
└── README.md         this file
```

## What to use for each environment

| Environment | Path |
| --- | --- |
| Local dev (single dev box) | `make bootstrap` → `infra/compose/docker-compose.yml` |
| CI kind smoke | `infra/helm/deploy-verify.sh` + `values.kind.yaml` |
| Shared dev cluster | `make helm-dev` → `values-dev.yaml` |
| Staging cluster | `make helm-staging` → `values-staging.yaml` |
| UAT cluster | `make helm-uat` → `values-uat.yaml` |
| Production cluster | `make helm-prod` → `values-prod.yaml` |

There are no Terraform modules in this repo — the chart assumes the
cluster, managed Postgres, OpenSearch, and object store are
pre-provisioned by the platform team's IaC tree (out of scope here).

## What used to live under `infra/k8s/`

A set of hand-rolled YAML manifests that mirrored a small subset of
the chart. They drifted continuously, had no security context, used
`:latest` tags, and were a tripping hazard for operators applying
"the YAML" instead of `helm install`. They were removed in the
2026-05 audit pass — use the chart.

If you genuinely need raw YAML for a constrained environment, render
the chart:

```bash
helm template vaultscan infra/helm/vaultscan -f infra/helm/vaultscan/values-dev.yaml > /tmp/render.yaml
kubectl apply -f /tmp/render.yaml
```
