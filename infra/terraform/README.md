# `infra/terraform/` — cloud-agnostic IaC

Provisions everything VaultScan needs to run: a Kubernetes cluster,
managed Postgres, object storage, search, and the application itself
(via the Helm chart in `../helm/vaultscan/`).

Designed for portability — the same composition runs on AWS, GCP,
Azure, or any plain Kubernetes cluster (bare metal, on-prem, k3s,
Rancher, etc.). Pick one when you start; the application layer
doesn't change.

## Why OpenTofu

OpenTofu is the default because it's MPL2 (vs Terraform's BSL after
1.6) and the configurations are byte-compatible. `terraform`
binaries built from a 1.5.x source also work. The CI checks both.

## Layout

```
infra/terraform/
├── README.md
├── versions.tf                  # shared version pins
├── modules/
│   ├── kubernetes/{aws,gcp,azure,generic}/    cluster provisioning
│   ├── database/{aws,gcp,azure,generic}/      managed Postgres
│   ├── object-storage/{aws,gcp,azure,generic} S3-equivalent
│   ├── opensearch/{aws,gcp,azure,generic}/    analytics index
│   └── vaultscan/                             cloud-agnostic Helm install
└── environments/
    ├── aws/{dev,staging,uat,prod}.tfvars      AWS environment overlays
    ├── gcp/                                   GCP, same shape
    ├── azure/                                 Azure, same shape
    └── generic/                               BYO Kubernetes
```

## Module contract

Every cloud-specific module under `modules/<thing>/<cloud>/` honors
the same input/output shape:

| Output | Type | Meaning |
| --- | --- | --- |
| `database.endpoint` | string | Postgres host:port |
| `database.dsn_secret_name` | string | k8s secret holding the DSN |
| `database.replica_endpoint` | string | empty if no replica configured |
| `object_storage.bucket_name` | string | bucket for evidence |
| `object_storage.endpoint_url` | string | SDK endpoint |
| `object_storage.access_credentials_secret_name` | string | k8s secret holding key + secret |
| `kubernetes.kubeconfig_path` | string | path to a usable kubeconfig |
| `kubernetes.cluster_name` | string | for kubectl context |
| `opensearch.endpoint` | string | https URL with port |

The `modules/vaultscan/` module consumes those shapes — it doesn't
know which cloud rendered them.

## Quick start

```bash
# 1. Pick a cloud + environment.
cd infra/terraform/environments/aws

# 2. Initialize.
tofu init     # or: terraform init

# 3. Set tfvars (or pass via -var-file).
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars

# 4. Plan + apply.
tofu plan  -var-file=dev.tfvars
tofu apply -var-file=dev.tfvars
```

The composition outputs the kubeconfig path + a list of Kubernetes
Secrets it created. The chart picks them up via
`secrets.existingSecret`.

## Switching clouds

```bash
# Same chart, different infra. The vaultscan module is identical.
cd infra/terraform/environments/gcp
tofu apply -var-file=prod.tfvars
```

## State backend

State stays out of this directory. Each environment composition has
its own `backend.tf` you can edit before `tofu init`. Recommended:

| Cloud | Backend | Why |
| --- | --- | --- |
| AWS | S3 + DynamoDB lock | native, lowest setup |
| GCP | GCS | server-side state-locking baked in |
| Azure | azurerm | native |
| generic | http (Gitlab) / consul / s3-compatible | operator's choice |

## What this doesn't cover

- DNS, ACME issuance — assumed pre-existing or managed by cert-manager
  via the Helm chart's `ingress.annotations`.
- Identity provider — Keycloak realm import via `infra/keycloak/` for
  the bundled dev path; production should plug in the customer's
  external IdP.
- WAF / DDoS — bring your own (Cloudflare, AWS Shield, etc.). The
  agent-gateway LoadBalancer doesn't fronts on a raw IP; production
  must put a WAF in front.

## Make targets

```bash
make tf-init     ENV=dev CLOUD=aws       # tofu init
make tf-plan     ENV=dev CLOUD=aws       # tofu plan -var-file=...
make tf-apply    ENV=prod CLOUD=aws      # production prompts before apply
make tf-destroy  ENV=dev CLOUD=generic   # destroy a non-prod env
```

## Cost note

The compositions provision real cloud resources. Read the `*.tfvars`
file before applying — `prod` overlays use multi-AZ HA Postgres,
3-AZ EKS/GKE/AKS node groups, and persistent storage that aren't
free. The `generic/` flavor on a single Linux box runs at the cost
of one VM.
