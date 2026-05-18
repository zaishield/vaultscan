# `infra/` layout

This directory holds every piece of deployment infrastructure for
VaultScan that lives outside the application code itself.

```
infra/
├── compose/          dev stack (docker-compose; not for staging+ use)
├── helm/             Helm chart — the supported in-cluster deploy
│   └── vaultscan/
│       ├── values.yaml            baseline (production-shaped)
│       ├── values-dev.yaml        single-replica overlay
│       ├── values-staging.yaml    2-replica + letsencrypt-staging
│       ├── values-uat.yaml        2-replica + Kyverno enforce
│       ├── values-prod.yaml       3-replica + every gate on
│       ├── values.kind.yaml       kind-cluster CI overlay
│       ├── templates/             deployment / service / ingress / RBAC / etc.
│       └── kind-cluster.yaml      kind config used by deploy-verify.sh
├── terraform/        cloud-agnostic IaC (OpenTofu / Terraform)
│   ├── modules/
│   │   ├── kubernetes/{aws,gcp,azure,generic}/    cluster provisioning
│   │   ├── database/{aws,gcp,azure,generic}/      managed Postgres
│   │   ├── object-storage/{aws,gcp,azure,generic} S3-equivalent
│   │   ├── opensearch/{aws,generic}/              analytics index
│   │   └── vaultscan/                             Helm install wrapper
│   └── environments/{aws,gcp,azure,generic}/
│       ├── main.tf  variables.tf  outputs.tf  backend.tf  versions.tf
│       ├── dev.tfvars  staging.tfvars  uat.tfvars  prod.tfvars
├── images/           images that are NOT the application binary
│   └── restore-verify/    alpine + pg_restore + awscli for the DR drill
├── keycloak/         realm-import JSON used by the compose stack
└── README.md         this file
```

## What to use for each environment

| Environment | Infra (one of) | App layer |
| --- | --- | --- |
| Local dev (single dev box) | n/a (docker-compose) | `make bootstrap` |
| Shared dev cluster | `make tf-apply CLOUD=… ENV=dev` | bundled in same apply (Helm chart) |
| Staging cluster | `make tf-apply CLOUD=… ENV=staging` | bundled |
| UAT cluster | `make tf-apply CLOUD=… ENV=uat` | bundled |
| Production cluster | `make tf-apply CLOUD=… ENV=prod` | bundled |
| CI kind smoke (chart only) | `infra/helm/deploy-verify.sh` | uses values.kind.yaml |

`CLOUD` is one of `aws | gcp | azure | generic`. The same composition
works against any of them — only the module sources differ. The
Helm chart is invoked from inside the Terraform composition; you
can also `make helm-<env>` separately if the cluster is already
provisioned.

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
