# vaultscan Helm chart

Deploys the ZAISHIELD VAULTSCAN platform — API, agent-gateway, portal,
analytics worker, and the schema migration job — as a single release.

## TL;DR

```bash
helm install vaultscan ./infra/helm/vaultscan \
  -n vaultscan --create-namespace \
  --set databases.external.postgresURL=postgres://... \
  --set databases.external.opensearchURL=https://... \
  --set databases.external.objectStoreURL=https://s3... \
  --set secrets.existingSecret=vaultscan-prod-env
```

## Required Secret

The chart expects a Secret (referenced via `secrets.existingSecret`) with:

```
VAULTSCAN_DATABASE_URL          # postgres://user:pass@host:5432/vaultscan?sslmode=require
VAULTSCAN_JWT_SECRET            # HS256 secret (or replace with Keycloak)
VAULTSCAN_EVIDENCE_MASTER_KEY   # base64-encoded 32-byte AES-256 master key
VAULTSCAN_JOB_SIGNING_KEY       # PEM-encoded RSA private key for scan job signing
VAULTSCAN_OBJECT_STORE_KEY      # access key id
VAULTSCAN_OBJECT_STORE_SECRET   # access key secret
```

## Components

| Component         | Image                             | Replicas         |
|-------------------|-----------------------------------|------------------|
| API control plane | `vaultscan/api`                   | 3 (HPA to 12)    |
| Agent gateway     | `vaultscan/agent-gateway`         | 3                |
| Portal            | `vaultscan/portal`                | 2                |
| Analytics worker  | `vaultscan/analytics-worker`      | 2                |
| Migrations        | `vaultscan/api` (runs `migrate`)  | 1 Job (pre-install / pre-upgrade) |

## Sizing baseline

Defaults match Blueprint §26 small-production:

- API: 3 × (1 cpu / 1 Gi) → 4 cpu / 8 Gi limits, HPA target 70 % CPU.
- Agent gateway: 3 × (1 cpu / 1 Gi) → 4 cpu / 4 Gi.
- Portal: 2 × 100 m / 128 Mi → 500 m / 256 Mi.
- Analytics worker: 2 × 200 m / 256 Mi → 2 cpu / 2 Gi.

## Production checklist

- [ ] `databases.external.*` set to managed services
- [ ] `secrets.existingSecret` references a SealedSecret / ExternalSecret
- [ ] Real EIP allocations in `agentGateway.service.annotations`
- [ ] Cert-manager issuer configured for both Ingress paths
- [ ] `networkPolicies.enabled: true` with the `vaultscan-tier=ingress`
      label applied to the ingress namespace
- [ ] `serviceMonitor.enabled: true` with Prometheus operator installed
- [ ] HS-06 acceptance matrix (`docs/slices/hs-06-acceptance.md`) signed off
