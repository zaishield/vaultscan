# VS-05 · External Scanner Plane

| Acceptance Criterion                                                                  | Implementation |
|---------------------------------------------------------------------------------------|----------------|
| End-to-end external scan runs and raw output arrives in storage                       | `scanorch.Submit` → tasks created → agent gateway upload writes to `evidence.Vault` |
| Each scan job runs in an isolated Kubernetes pod with no shared volumes               | Per-job `scan_tasks` row; `infra/k8s/scanner-farm` (HS-03) defines NetworkPolicy + ResourceQuota per scanner namespace |
| Pod destroyed and temp artifacts cleaned                                              | Production controller pattern in `tools/scanner-images/` Dockerfiles; orchestrator marks task `completed_at` |
| Scanner region selection routes to correct node pool                                  | `scanorch.pickScannerNode` filters `scanner_node_registry` by region |
| All tool containers pass image signature verification                                 | `scan_tasks.image_digest` recorded; production uses cosign verify (Helm chart pre-pull) |
| CPU, memory, runtime limits enforced; job killed if exceeded                          | `scan_tasks` columns `cpu_limit`, `memory_limit`, `runtime_limit_s`; agent runner enforces locally; K8s limits in scanner farm chart |
| Scope Guard blocks out-of-scope targets before job creation                           | `scanorch.Submit` evaluates Scope Guard per-target before persisting the job |

## Tools containerized (Blueprint §15)

Nmap, Naabu, httpx, Amass, Subfinder, dnsx, Nuclei, OWASP ZAP, testssl.sh,
sslyze, Katana, ffuf — declared in `tools/scanner-images/<tool>/Dockerfile`.

## Regional scanner registry

Seeded with 5 default regions in `0010_seed_platform.up.sql`
(ae, eu, in, us, sg) with static public IPs and abuse contact strings, per
Blueprint §5.4 and §5.5.

## Key files

- `backend/internal/scanorch/orchestrator.go`
- `backend/migrations/0005_scans_scanners.up.sql`
- `backend/cmd/agent-gateway/main.go` (results upload)
- `infra/k8s/scanner-farm/`
- `frontend/src/pages/{ExternalScans,ScanJobs}.tsx`
