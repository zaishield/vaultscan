# ZAISHIELD VAULTSCAN

Enterprise Hybrid Vulnerability Assessment & Penetration Testing Platform.

VAULTSCAN is a multi-tenant, multi-brand, cloud-managed hybrid VA/PT platform that
enables enterprises, MSSPs, distributors, and resellers to conduct external
attack-surface assessments and internal network security assessments through one
branded portal.

This repository implements the platform per the **Master Blueprint** and
**Full Development Plan**, using the vertical-first slice methodology (12 vertical
slices followed by 6 horizontal slices).

---

## Repository Layout

```
vaultscan/
├── backend/        Go control-plane services, REST API, scan orchestrator, parsers
├── frontend/       React + TypeScript + Tailwind branded portal
├── agent/          Go binary for the silent internal agent
├── infra/          docker-compose, Kubernetes, Helm, Terraform, Kong, Keycloak
├── tools/          Containerized scanner images, supporting scripts
└── docs/           Architecture notes, slice ledger, runbooks
```

## Vertical Slice Status

| Slice | Name | Status |
|-------|------|--------|
| VS-01 | Platform Foundation & Auth | implemented |
| VS-02 | Partner & White-Label Engine | implemented |
| VS-03 | Engagement & Scope Guard | implemented |
| VS-04 | Asset Discovery & Management | implemented |
| VS-05 | External Scanner Plane | implemented |
| VS-06 | Internal Agent Plane | implemented |
| VS-07 | Findings Engine | implemented |
| VS-08 | Evidence Vault | implemented |
| VS-09 | Retesting Workflow | implemented |
| VS-10 | Reporting Engine | implemented |
| VS-11 | Integrations & Event Bus | implemented |
| VS-12 | Dashboards & Visualization | implemented |

## Horizontal Slice Status

| Slice | Name | Status |
|-------|------|--------|
| HS-01 | Security Hardening & Pen Test | implemented |
| HS-02 | Audit & Compliance Hardening | implemented |
| HS-03 | Production Infrastructure | implemented |
| HS-04 | Performance & Scale Testing | implemented |
| HS-05 | Operational Guardrails & Policy | implemented |
| HS-06 | Full Blueprint Acceptance Test | implemented |

See `docs/slices/` for the per-slice ledger mapping each acceptance criterion to
the implementation artifact that satisfies it.

---

## Local Development

Prerequisites: Docker + Docker Compose, Go 1.22+, Node.js 20+, Make.

```bash
make bootstrap        # build images, run DB migrations, seed Keycloak
make up               # start the full stack via docker-compose
make seed             # load demo tenants, partners, engagements, assets
make test             # run backend + frontend tests
```

Default URLs:

- Portal:        http://localhost:5173
- API gateway:   http://localhost:8080
- Keycloak:      http://localhost:8081
- OpenSearch:    http://localhost:9200
- MinIO console: http://localhost:9001

Default credentials are documented in `docs/operations/local-dev.md`.

---

## Blueprint Reference

This codebase is structured to map 1:1 with the Master Blueprint. Each row
below points at a path that exists in this repository.

| Blueprint section          | Implementation                                                                       |
|----------------------------|--------------------------------------------------------------------------------------|
| §5 External VA/PT Plane    | `backend/internal/scanorch/`, `infra/k8s/scanner-farm/`                              |
| §6 Internal VA/PT Plane    | `backend/cmd/agent-gateway/`, `agent/`                                               |
| §7 Cloud Portal UI         | `frontend/`                                                                          |
| §8 White-Label Engine      | `backend/internal/branding/`, `backend/internal/partners/`                           |
| §9 Multi-Tenant Hierarchy  | `backend/internal/tenants/`, `backend/internal/middleware/middleware.go` (`TenantScope`) |
| §11 Control Plane Services | `backend/internal/*` service packages, `backend/cmd/api/`                            |
| §13 Internal Agent         | `agent/`                                                                             |
| §14 Scope Guard            | `backend/internal/scopeguard/`                                                       |
| §15 Tool-Domain Mapping    | `tools/scanner-images/`, `backend/internal/parsers/`                                 |
| §17 Findings Engine        | `backend/internal/findings/`                                                         |
| §18 Evidence Vault         | `backend/internal/evidence/`                                                         |
| §19 Reporting Engine       | `backend/internal/reporting/`                                                        |
| §20 Database               | `backend/migrations/`                                                                |
| §21 API                    | `backend/internal/api/`                                                              |
| §22 Event Bus              | `backend/internal/eventbus/`                                                         |
| §23 RBAC                   | `backend/internal/auth/`, roles + permissions seeded in `backend/migrations/0001_platform_foundation.up.sql` |
| §24 Security               | see [HS-01 ledger](docs/slices/hs-01-security-hardening.md)                          |
| §29 SSO/MFA                | `infra/keycloak/`, `backend/internal/auth/`, `backend/internal/middleware/middleware.go` (`RequireMFA`) |
| §30 Secrets                | `backend/internal/secrets/`                                                          |
| §32 Compliance & Audit     | `backend/internal/audit/`, see [HS-02 ledger](docs/slices/hs-02-audit-compliance.md) |
| §36 Guardrails             | see [HS-05 ledger](docs/slices/hs-05-guardrails.md)                                  |
| §37 Acceptance Checklist   | see [HS-06 ledger](docs/slices/hs-06-acceptance.md)                                  |
