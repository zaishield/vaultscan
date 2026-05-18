# Platform admin — Day 1

**Primary objective:** stand up a fresh VaultScan deployment ready
for the first customer signup. ~4 hours of focused work.

This is what you do the FIRST time. Day-to-day ops live in
`docs/operations/*.md`; release work lives in `release-runbook.md`.

## Prereqs (before starting)

- [ ] A Kubernetes cluster reachable (any cloud + the bundled
      Terraform compositions; see `infra/terraform/`)
- [ ] Object store for evidence vault (S3 / GCS / Azure Blob; in
      kind: the bundled MinIO from `make tf-local-up`)
- [ ] Managed Postgres OR in-cluster (in kind: bundled)
- [ ] OpenSearch (in kind: deployed by the operator chart)
- [ ] KMS / Vault for the master KEK (in dev: env var; in prod: KMS)
- [ ] An IdP for customer auth (Keycloak in dev / cloud-IdP in prod)
- [ ] DNS + TLS certs for `api.<your>` + `portal.<your>` (cert-manager + Let's Encrypt is the chart's default)
- [ ] Cosign sign-on identity for image verification (GitHub OIDC by default)
- [ ] An on-call paging rotation set up (PagerDuty / Opsgenie)

## Step 1 — Apply infrastructure

```bash
cd infra/terraform/environments/aws    # or gcp / azure / generic
cp dev.tfvars myprod.tfvars
$EDITOR myprod.tfvars                   # set tenants, sizes, region

make tf-init    CLOUD=aws ENV=prod
make tf-plan    CLOUD=aws ENV=prod     # review carefully
make tf-apply   CLOUD=aws ENV=prod     # production prompts before applying
```

Terraform provisions: VPC + EKS/GKE/AKS + managed Postgres + S3/GCS
+ OpenSearch + IAM + secrets. Output: kubeconfig path + the
consolidated env secret in the cluster.

## Step 2 — Deploy the chart

```bash
helm upgrade --install vaultscan ./infra/helm/vaultscan \
  -n vaultscan --create-namespace \
  -f ./infra/helm/vaultscan/values-prod.yaml \
  --set networkPolicies.externalEgress.cidrBlocks='{10.0.0.0/8}'
```

The migrations Job runs as a pre-install hook; watch:

```bash
kubectl logs -n vaultscan job/vaultscan-migrate -f
# Expected last line: "✓ migrate complete: applied 58 migrations"
```

## Step 3 — Verify the cluster is healthy

```bash
kubectl get pods -n vaultscan
# All pods should reach Running + Ready within 2 min.

curl https://api.<your>/readyz
# Returns "ok" when DB + bus + audit chain are all reachable.

curl https://api.<your>/api/v1/status | jq
# {"version":"1.0.0","uptime_s":...,"components":{...}}
```

## Step 4 — Cut the first release tag (populates digests.json)

```bash
# Without this step, scanner submissions REFUSE in strict mode.
git tag -s v1.0.0 -F /dev/stdin <<EOF
First GA release
EOF
git push origin v1.0.0
```

`.github/workflows/security.yml` will:
1. Build + cosign-sign every scanner image
2. Capture immutable digests into `tools/scanner-images/digests.json`
3. Commit that file back to main

Watch:
```bash
gh run watch --workflow=security.yml --exit-status
```

After the workflow lands, every `helm upgrade` from main pulls the
populated digests; scanner dispatch succeeds in strict mode.

## Step 5 — Configure JWT signing keys

```bash
ADMIN_JWT=$(curl -s -X POST https://api.<your>/api/v1/auth/dev-token \
  -d '{"email":"admin@zaishield.com","roles":["zaishield_super_admin"]}' \
  | jq -r .token)

# Initial keys are auto-generated. Verify they exist via the JWKS:
curl https://api.<your>/.well-known/jwks.json | jq '.keys | length'
# >= 1 active key

# Rotate now to take ownership of key material:
curl -X POST "https://api.<your>/api/v1/auth/jwt-keys/rotate" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

## Step 6 — Provision an MFA admin user

In production the dev-token endpoint is OFF. Create the first real
admin user via SCIM + your IdP, OR via direct DB insert + IdP
federation. See `docs/operations/jwt-key-rotation.md` + the IdP's
own SCIM connector docs.

## Step 7 — Sign up the first partner

```bash
curl -X POST "https://api.<your>/api/v1/partners" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name":"Acme Cyber",
    "slug":"acme-cyber",
    "type_code":"distributor",
    "plan":"enterprise"
  }'
```

Then onboard tenants under that partner via `customer-onboarding.md`.

## Step 8 — Wire monitoring

```bash
# Apply the ServiceMonitor + PrometheusRule (chart includes them):
kubectl get servicemonitor -n vaultscan
kubectl get prometheusrule -n vaultscan

# Hook your Alertmanager to the SMTP / PagerDuty / Slack receiver
# for each severity (alerts.yaml ships sane defaults).
```

## Step 9 — Test the DR drill

```bash
make backup-snapshot    # against the new cluster's DB
./tools/scripts/dr-drill.sh
# walks: backup → fresh-Postgres → restore → row-count verify
# → audit-chain verify-deep → GA-table existence check
```

If the drill passes, you can sign customer SLAs with confidence.

## Step 10 — Cron-runner verification

```bash
kubectl logs -n vaultscan -l app=vaultscan-cron-runner --tail=50 | \
  grep "cron-runner started"
# Expected: "jobs": 18 (or whatever the current count is per
# cmd/cron-runner/main.go)
```

Every task name in the comment block at the top of that file should
show up in the logs within an hour.

## Where to go next

| What | Where |
| --- | --- |
| Per-environment configuration | `infra/helm/vaultscan/values-*.yaml` |
| Operator runbooks | `docs/operations/*.md` (29+ files) |
| New customer onboarding | `customer-onboarding.md` |
| Incident response | `incident-response.md` + per-symptom runbooks |
| Capacity validation | `capacity-validation-runbook.md` |
| Pentest engagement | `pentest-engagement-runbook.md` |

## Day 1 acceptance checklist

- [ ] Terraform applied; all four envs (or chosen one) provisioned
- [ ] Chart deployed; every workload Ready
- [ ] /readyz returns ok
- [ ] v1.0.0 tag pushed; digests.json populated
- [ ] JWT keys rotated to take ownership
- [ ] At least one admin user can sign in via the IdP
- [ ] First partner + tenant created via API
- [ ] cron-runner reports the expected job count
- [ ] DR drill passes
- [ ] Prometheus / Grafana dashboards show non-zero metrics
- [ ] On-call rotation receives a test page

Sign-off: CTO / Head of Engineering before any customer traffic.
