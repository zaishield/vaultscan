# Running the `generic` Terraform on a local machine

The generic flavor (BYO Kubernetes) is the path for running every
environment — dev, staging, UAT, prod — on a laptop. Each environment
lives in its own kind cluster + its own Terraform workspace, so they
can coexist without state collision.

## Prerequisites

| Tool | Why | Install |
| --- | --- | --- |
| Docker | kind runs nodes as containers | https://docs.docker.com/engine/install/ |
| kind | the Kubernetes cluster | `brew install kind` / `go install sigs.k8s.io/kind@latest` |
| kubectl | inspecting the cluster | https://kubernetes.io/docs/tasks/tools/ |
| OpenTofu (or Terraform 1.5+) | applying the composition | `brew install opentofu` / https://opentofu.org/docs/intro/install/ |
| Helm 3.13+ | the providers use Helm under the hood | `brew install helm` |

## Resource budget

| Env | RAM | CPU | Disk |
| --- | --- | --- | --- |
| dev      | 2 GB | 2 cores | 5 GB |
| staging  | 3 GB | 3 cores | 10 GB |
| uat      | 4 GB | 3 cores | 15 GB |
| prod     | 6 GB | 4 cores | 25 GB |

Running all four concurrently needs ~16 GB free + ~55 GB Docker disk.
On a 16 GB laptop, bring them up **one at a time** (the Make targets
already serialize when you use `tf-local-up-all`).

## Quick start — one environment

```bash
# From the repo root.
make tf-local-up ENV=dev
```

Under the hood:
1. `tools/scripts/local-cluster.sh up dev` creates a kind cluster
   named `vaultscan-dev` (context: `kind-vaultscan-dev`).
2. `tofu init` initializes the generic composition.
3. `tofu workspace select -or-create dev` picks/creates the workspace
   so dev/staging/uat/prod have separate state files.
4. `tofu apply -var-file=dev.tfvars -var=local_overrides_enabled=true`
   provisions Postgres + MinIO + OpenSearch operator in-cluster and
   installs the VaultScan Helm chart with the dev overlay.

The `local_overrides_enabled=true` flag layers `local-overrides.yaml`
on top of the env overlay — it disables Ingress, LoadBalancer
services, Kyverno cosign verification, and pgbouncer (none of which
work on a vanilla kind cluster without extra setup).

Once it's up:

```bash
make tf-local-portforward ENV=dev
# → API at http://localhost:8080, portal at http://localhost:5173
```

Ctrl-C the port-forward when done.

## All four environments

```bash
make tf-local-up-all      # serialised: dev → staging → uat → prod
make tf-local-status      # see what's running

# When you're done:
make tf-local-down-all
```

Each environment is in its own kind cluster, so port-forwards from
two of them at once need different host ports:

```bash
# Terminal 1
kubectl --context kind-vaultscan-dev    -n vaultscan port-forward svc/vaultscan-api 8080:8080
# Terminal 2
kubectl --context kind-vaultscan-staging -n vaultscan port-forward svc/vaultscan-api 8081:8080
```

## Switching between envs

`kubectl` follows the context. The Make targets always pin via
`--context kind-vaultscan-$ENV` so you don't need to remember which
one is active. For ad-hoc work:

```bash
kubectx kind-vaultscan-uat   # if you have kubectx
# or
kubectl config use-context kind-vaultscan-uat
```

## Inspecting state

Terraform stores per-workspace state under:

```
infra/terraform/environments/generic/terraform.tfstate.d/<env>/terraform.tfstate
```

Switch and inspect:

```bash
tofu -chdir=infra/terraform/environments/generic workspace select uat
tofu -chdir=infra/terraform/environments/generic show
tofu -chdir=infra/terraform/environments/generic output
```

## Tearing one env down

```bash
make tf-local-down ENV=staging
```

This `tofu destroy`s the workspace, then deletes the kind cluster,
then removes the Terraform workspace. Idempotent — safe to re-run.

## Common issues

**"context not found"**

You ran `tf-local-up` but the kind cluster wasn't created (Docker
not running, or the previous run errored). Re-run; the script
detects an existing cluster and reuses it.

**"insufficient memory" or kind nodes restarting**

Docker Desktop's default RAM limit (4 GB on macOS) is too small.
Settings → Resources → bump RAM to 12 GB+ for one env, 16 GB for all
four. On Linux, kind uses host RAM directly so no Docker setting.

**"helm timeout waiting for resource"**

The in-cluster Postgres/MinIO/OpenSearch are still pulling images
on first apply. Re-run `make tf-local-up ENV=<x>` — it picks up
where it left off. If it persists, check `kubectl --context
kind-vaultscan-<env> get pods -A` for pull errors.

**OpenSearch operator pod CrashLoopBackOff**

The OpenSearch operator's webhook needs cert-manager OR the
chart's bundled self-signed certs to provision. The chart we
install (`opensearch-operator`) ships with self-signed by default.
If it loops, delete the operator namespace and re-apply:

```bash
kubectl --context kind-vaultscan-<env> delete ns opensearch-operator-system
make tf-local-up ENV=<env>
```

**Need ingress on a non-dev env locally**

The script installs `ingress-nginx` automatically for staging/uat/
prod kind clusters, and maps host ports 80/443 to the kind node.
But the chart overlays' Ingress hostnames
(`api-staging.vaultscan.zaishield.com`) don't resolve. Either edit
your `/etc/hosts` to point them at 127.0.0.1, or stick with the
`port-forward` flow.

## Different from `make bootstrap`

`make bootstrap` uses docker-compose for the absolute fastest
local-dev loop. The Terraform local flow is heavier but exercises
exactly the same code paths as the cloud envs — the same Helm
chart, same security gates, same observability wiring. Use it
when you need to validate a deploy-shape change before pushing to
staging/UAT.
