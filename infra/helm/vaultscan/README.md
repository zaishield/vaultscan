# vaultscan Helm chart

Deploys the ZAISHIELD VAULTSCAN platform — API, agent-gateway, portal,
analytics worker, cron-runner, schema migration job, and (optionally)
per-region scanner workers + pgBouncer + backup CronJobs — as a single
release.

## Per-environment install

Each environment has its own values overlay; pick one rather than
running off the bare `values.yaml`:

```bash
# Local / dev cluster
make helm-dev          # uses values-dev.yaml

# Staging
make helm-staging      # uses values-staging.yaml

# Customer-acceptance / UAT
make helm-uat          # uses values-uat.yaml

# Production (prompts for confirmation, runs `helm diff` first)
make helm-prod         # uses values-prod.yaml
```

The default `values.yaml` is the **production baseline**. Don't install
it directly — install one of the overlays.

Direct `helm install` (no Makefile):

```bash
helm upgrade --install vaultscan ./infra/helm/vaultscan \
  -n vaultscan --create-namespace \
  -f ./infra/helm/vaultscan/values-prod.yaml \
  --set databases.external.postgresURL=postgres://... \
  --set databases.external.opensearchURL=https://... \
  --set databases.external.objectStoreURL=https://s3...
```

## Required Secret

The chart expects a Secret (referenced via `secrets.existingSecret`) with:

```
VAULTSCAN_DATABASE_URL          # postgres://user:pass@host:5432/vaultscan?sslmode=require
VAULTSCAN_DATABASE_REPLICA_URL  # optional: read-replica DSN; empty = no replica
VAULTSCAN_JWT_SECRET            # HS256 secret (or replace with Keycloak)
VAULTSCAN_EVIDENCE_MASTER_KEY   # base64-encoded 32-byte AES-256 master key (KEK)
VAULTSCAN_JOB_SIGNING_KEY       # PEM-encoded RSA private key for scan job signing
VAULTSCAN_OBJECT_STORE_KEY      # access key id
VAULTSCAN_OBJECT_STORE_SECRET   # access key secret
```

Use a `SealedSecret` or `ExternalSecret` to populate this in production —
never inline the values via `secrets.inline.*`.

## Components

| Component         | Image                             | Replicas (prod baseline) |
|-------------------|-----------------------------------|--------------------------|
| API control plane | `vaultscan/api`                   | 3 (HPA to 12)            |
| Agent gateway     | `vaultscan/agent-gateway`         | 3                        |
| Portal            | `vaultscan/portal`                | 3                        |
| Analytics worker  | `vaultscan/analytics-worker`      | 2                        |
| Cron-runner       | `vaultscan/cron-runner`           | 2 (leader-elected)       |
| Migrations        | `vaultscan/api` (runs `migrate`)  | 1 Job (pre-install / pre-upgrade) |
| Scanner workers   | `vaultscan/scanner-worker`        | per-region; opt-in       |
| pgBouncer (tx)    | `bitnami/pgbouncer`               | 3 (prod)                 |
| pgBouncer (sess)  | `bitnami/pgbouncer`               | 2 (prod)                 |
| Backup CronJob    | `vaultscan/backup`                | 1, daily                 |
| Restore-verify    | `vaultscan/restore-verify`        | 1 CronJob, daily         |

## What cron-runner does (don't disable it)

Cron-runner is the leader-elected background worker that drives
every periodic task in the platform. Disabling it silently breaks
the following Blueprint §22.4 features:

- SLA-breach sweep + auto-flagging
- DEK rotation + per-tenant re-wrap of evidence (KEK/DEK pipeline)
- Audit chain VerifyDeep forensics
- Partition maintenance for the partitioned tables
- SIEM batch shipping
- Scheduled report generation
- Integration dead-letter depth metric refresh
- Agent telemetry rollup

It is leader-elected via Postgres advisory locks, so running 2
replicas is safe and recommended for HA-during-rolling-restart.

## Sizing baseline (prod defaults)

| Component       | Per-replica request | Per-replica limit | Replicas |
| --------------- | ------------------- | ----------------- | -------- |
| api             | 1 cpu / 1 Gi        | 4 cpu / 8 Gi      | 3 → 12 (HPA) |
| agent-gateway   | 1 cpu / 1 Gi        | 4 cpu / 4 Gi      | 3        |
| portal          | 100 m / 128 Mi      | 500 m / 256 Mi    | 3        |
| analytics-worker| 200 m / 256 Mi      | 2 cpu / 2 Gi      | 2        |
| cron-runner     | 100 m / 128 Mi      | 1 cpu / 1 Gi      | 2        |

See `docs/operations/capacity-planning.md` for the load-driver model.

## Knobs exposed via the ConfigMap

The chart's ConfigMap (rendered from `values.yaml`) carries every
env var the binaries read, including the GA additions:

- `VAULTSCAN_REGION` — for data-residency enforcement
- `VAULTSCAN_DATABASE_REPLICA_URL` — read-replica routing
- `VAULTSCAN_REQUIRE_INBOUND_SIG` — refuse unsigned webhook callbacks
- `VAULTSCAN_REQUIRE_SIGNED_IMAGES` — refuse unsigned scanner images
- `VAULTSCAN_RATE_LIMIT_{RPS,WINDOW_SEC,TENANT_MULTIPLIER,BACKEND,REDIS_ADDR}`
- `VAULTSCAN_AUDIT_EXPORT_HARD_CAP` — bounds the audit export pull
- `VAULTSCAN_DEK_ROTATION_DAYS` / `VAULTSCAN_DEK_REWRAP_BATCH`
- `VAULTSCAN_OTEL_EXPORTER` + `VAULTSCAN_OTEL_ENDPOINT` — tracing

Override any of these via `values.yaml` (or the per-env overlay).

## Multi-region deployments

Each region is a separate cluster + separate Helm release. Set
`global.region` on every pod so the data-residency gate refuses
cross-region writes when a tenant is pinned. The recommended
pattern is one regional `values-prod-<region>.yaml` overlay that
sets:

- `global.region: eu`
- `api.ingress.hosts[0].host: api-eu.vaultscan.zaishield.com`
- `portal.ingress.hosts[0].host: eu.vaultscan.zaishield.com`
- `databases.external.*` pointing at region-local managed services
- `scannerWorker.regions: [{name: eu-west-1, replicaCount: 2}]`

Layer it on top of the baseline:

```bash
helm upgrade --install vaultscan ./infra/helm/vaultscan \
  -f ./infra/helm/vaultscan/values-prod.yaml \
  -f ./infra/helm/vaultscan/values-prod-eu.yaml
```

## Scanner-image digest pinning

`scannerWorker.imageRegistry` points at the registry hosting the
per-tool images (nuclei, zap, nmap, …). Production pulls are
digest-pinned via `tools/scanner-images/digests.json` which the
`security.yml` workflow rewrites on every `v*` release tag.

On a fresh `main` (no release tag yet) `digests.json` is empty
and the orchestrator falls back to `:latest` — the boot log will
carry a warning. To populate `digests.json` ahead of a real
release, push a temporary `v0.0.0-pin` tag.

## Production checklist

- [ ] `make helm-prod` (or equivalent) used — never `helm install`
      with no overlay
- [ ] `databases.external.*` set to managed Postgres / OpenSearch /
      S3-compatible object store
- [ ] `secrets.existingSecret` references a SealedSecret / ExternalSecret
      (NOT inline values)
- [ ] `global.region` set per-cluster
- [ ] Real EIP allocations in `agentGateway.service.annotations`
- [ ] Cert-manager `letsencrypt-prod` issuer configured for both
      Ingress paths
- [ ] `networkPolicies.enabled: true` with the `vaultscan-tier=ingress`
      label applied to the ingress namespace
- [ ] `serviceMonitor.enabled: true` and `metrics.prometheusRule.enabled: true`
      with Prometheus operator installed
- [ ] `kyverno.cosignVerifyPolicy.enabled: true` with Kyverno installed
- [ ] `backup.enabled: true` AND `restoreVerify.enabled: true`
- [ ] `pgbouncer.enabled: true`
- [ ] First release tag (`v*`) cut so `digests.json` is populated
- [ ] HS-06 acceptance matrix (`docs/slices/hs-06-acceptance.md`) signed off
