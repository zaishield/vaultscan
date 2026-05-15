# Local Development Guide

How to run the full VAULTSCAN stack on a workstation, with the default
credentials each component ships with for development.

> **None of these credentials are safe outside a developer laptop.** Production
> deployments use Keycloak SSO + Vault-backed secrets per Blueprint §29 and §30.
> Refer to `infra/helm/vaultscan/README.md` for the production checklist.

---

## Prerequisites

| Tool            | Minimum version | Verify                    |
|-----------------|-----------------|---------------------------|
| Docker / Compose| 24+             | `docker version`          |
| Go              | 1.22+           | `go version`              |
| Node.js         | 20+             | `node --version`          |
| Make            | any GNU make    | `make --version`          |

---

## One-shot bootstrap

```bash
make bootstrap        # build images + start stack + run migrations
make seed             # optional: load demo tenants/engagements/findings
```

`make up` and `make down` toggle the running stack afterwards. `make logs`
tails everything.

---

## Default URLs

| Surface           | URL                          | Override env                       | Notes |
|-------------------|------------------------------|-----------------------------------|-------|
| Portal            | http://localhost:5173        | `VAULTSCAN_PORTAL_PORT`           | nginx-served Vite build |
| API gateway       | http://localhost:8080        | `VAULTSCAN_API_PORT`              | `/healthz` + `/readyz` for probes |
| Agent gateway     | http://localhost:8443        | `VAULTSCAN_AGENT_GATEWAY_PORT`    | outbound-only TLS endpoint |
| Keycloak admin    | http://localhost:8081/admin  | `VAULTSCAN_KEYCLOAK_PORT`         | realm: `vaultscan` |
| OpenSearch        | http://localhost:9200        | `VAULTSCAN_OPENSEARCH_PORT`       | security plugin disabled in dev |
| MinIO API         | http://localhost:9000        | `VAULTSCAN_MINIO_PORT`            | S3-compatible |
| MinIO Console     | http://localhost:9001        | `VAULTSCAN_MINIO_CONSOLE_PORT`    | web UI |
| Postgres          | postgres://localhost:5432    | `VAULTSCAN_POSTGRES_PORT`         | psql client |

### Port conflicts

Every published host port is overridable. `make doctor` (run automatically by
`make bootstrap`) flags conflicts before any container starts. To resolve:

```bash
# One-off override
VAULTSCAN_OPENSEARCH_PORT=19200 make bootstrap

# Or persist in .env (auto-generated from .env.example by `make env`)
echo VAULTSCAN_OPENSEARCH_PORT=19200 >> .env
make bootstrap
```

---

## Default credentials (development only)

| Component         | Username / Identity      | Password / Secret                                |
|-------------------|--------------------------|--------------------------------------------------|
| Postgres          | `vaultscan`              | `vaultscan`                                      |
| Postgres database | `vaultscan`              | n/a                                              |
| MinIO root user   | `vaultscan`              | `vaultscan-dev-secret`                           |
| Keycloak admin    | `admin`                  | `admin`                                          |
| OpenSearch initial admin | `admin`           | `Vaultscan-Dev-9!` (only if security plugin enabled) |
| Agent enrollment  | one-time token returned by `POST /api/v1/agents` | revealed once, hashed in DB |

### Portal sign-in

In dev mode there is **no Keycloak user pre-seeded**. Sign-in mints a
self-signed JWT via the development endpoint:

```
POST /api/v1/auth/dev-token
{
  "user_id":    "00000000-0000-0000-0000-000000000001",
  "email":      "admin@zaishield.com",
  "full_name":  "Dev Admin",
  "platform_id":"00000000-0000-0000-0000-0000000000a1",
  "partner_id": "00000000-0000-0000-0000-0000000000b1",
  "tenant_id":  "00000000-0000-0000-0000-000000000c01",
  "roles":      ["zaishield_super_admin"],
  "mfa":        true
}
```

The Login page already submits this for you — pick the role(s) you want and
hit `INITIATE SESSION`. **The endpoint refuses to issue tokens when
`VAULTSCAN_ENV != development`.**

### Recommended demo identities

| Identity                          | Roles                                  |
|-----------------------------------|----------------------------------------|
| `admin@zaishield.com`             | `zaishield_super_admin`                |
| `dist@acme-distributor.com`       | `distributor_admin`                    |
| `mssp-manager@acme-mssp.com`      | `mssp_manager`                         |
| `pentester@acme-mssp.com`         | `pentester`                            |
| `client@example-customer.com`     | `client_viewer`                        |

---

## Seed data

`make seed` populates:

- ZAISHIELD platform + direct partner (already seeded by migrations)
- One distributor, one reseller-MSSP, one direct customer tenant
- A draft engagement with one approved scope target
- An enrolled agent stub for the customer tenant
- Sample assets covering 6 asset types
- A handful of normalised findings spanning critical/high/medium

After seeding, sign in with `admin@zaishield.com` and you'll see populated
dashboards.

---

## Common workflows

### Run only the backend (against host Postgres)

```bash
docker run -d --name vs-pg \
  -e POSTGRES_DB=vaultscan -e POSTGRES_USER=vaultscan -e POSTGRES_PASSWORD=vaultscan \
  -p 5432:5432 postgres:16
make migrate
cd backend && go run ./cmd/api
```

### Run the portal against a remote API

```bash
cd frontend
VITE_API_BASE=https://staging.api.vaultscan.zaishield.com npm run dev
```

### Run the agent locally

```bash
# 1) Provision an agent via the portal -> Internal Agents page; copy the
#    enrollment token.
# 2) Run the binary:
cd agent
go run ./cmd/agent \
  --gateway http://localhost:8443 \
  --agent-id <UUID-FROM-PORTAL> \
  --enroll-token <ONE-TIME-TOKEN> \
  --data-dir /tmp/vaultscan-agent
```

### Reset everything

```bash
make down
docker volume rm $(docker volume ls -q -f name=vaultscan)
rm -rf /tmp/vaultscan-evidence /tmp/vaultscan-agent
```

---

## Rotating dev secrets

Even for development, regenerate the evidence master key periodically so
the test fixtures don't drift onto shared machines:

```bash
openssl rand -base64 32   # paste into VAULTSCAN_EVIDENCE_MASTER_KEY
openssl genrsa 2048 | sed 's/$/\\n/' | tr -d '\n'   # VAULTSCAN_JOB_SIGNING_KEY
```

---

## Troubleshooting

| Symptom                                              | Fix                                       |
|------------------------------------------------------|-------------------------------------------|
| `migrate` fails with `relation already exists`       | Reset volume (`docker volume rm vaultscan-pg`) and re-run |
| Portal renders default ZAISHIELD branding everywhere | Branding store uses the host header — set `VAULTSCAN_BRANDING_DEFAULT` to a partner slug that exists |
| Agent never appears online                            | Confirm `agent-gateway` is reachable and `X-Agent-Cert-Fingerprint` matches `agent_certificates.fingerprint` |
| Scope Guard blocks every scan                        | Engagement must be active AND have an authorization document AND have approved scope targets matching the plane |
| Evidence download returns `invalid or expired signature` | URLs expire after 5 minutes — request a fresh one via `GET /api/v1/evidence/{id}/url` |
