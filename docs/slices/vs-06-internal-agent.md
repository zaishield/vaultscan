# VS-06 · Internal Agent Plane

| Acceptance Criterion                                                              | Implementation |
|-----------------------------------------------------------------------------------|----------------|
| Agent enrolls via one-time token and receives signed certificate                  | `backend/internal/agents/service.go` `Provision` issues bcrypt-hashed token; `Enroll` consumes & stores cert |
| Agent connects outbound only; no listening port on customer network               | `agent/cmd/agent/main.go` only initiates HTTP requests to `--gateway`; no `net.Listen` |
| Unsigned job rejected by agent with audit log entry                               | `agent/internal/verifier/verifier.go` `Verify`; rejection emits `postStatus(failed, "signature verification failed")` |
| Out-of-scope target blocked by agent policy enforcer                              | `agent/internal/policy/policy.go` `AllowsTarget` - blocked scopes win, then allow list, CIDR-aware |
| Emergency stop halts all running jobs within 30 seconds                           | `agent/internal/emergency/emergency.go` atomic flag checked in poll loop and per-tool execution |
| All uploaded evidence encrypted; plaintext never touches cloud storage            | `agent/internal/cache/cache.go` AES-256-GCM cache; cloud `evidence.Vault` re-encrypts at rest |
| Agent heartbeat screen shows all 12 columns from §33.3                            | `frontend/src/pages/InternalAgents.tsx` table renders all 12 columns |
| CPU and memory limits enforced; scan throttled when exceeded                      | `agent/internal/policy/policy.go` `MaxCPUPercent` / `MaxMemoryPercent`; passed to runner |

## Form factors (Blueprint §13.1)

`linux_vm`, `docker`, `k8s`, `hardware`, `windows_service` — selectable on agent
provision (default `linux_vm`).

## Key files

- `agent/cmd/agent/main.go`
- `agent/internal/{enroll,heartbeat,policy,verifier,runner,packager,uploader,cache,emergency}/...`
- `backend/cmd/agent-gateway/main.go`
- `backend/internal/agents/service.go`
- `frontend/src/pages/InternalAgents.tsx`
