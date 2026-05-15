# HS-01 · Security Hardening & Penetration Test

| Acceptance Criterion                                                       | Implementation |
|----------------------------------------------------------------------------|----------------|
| No plaintext secrets in any DB field, log file, or env var                 | Integrations store `secret_ref`; agent certs PEM-only; evidence master key consumed via env in dev, OpenBao/Infisical in prod (`backend/internal/secrets/secrets.go`) |
| mTLS verified between every pair of internal services                      | Agent gateway terminates mTLS via cert fingerprint check; Helm chart configures Linkerd / Istio mesh in `infra/k8s/` |
| SAST scan: zero unresolved critical/high findings                          | CI runs Semgrep + go vet (`Makefile` `vet` target); no findings as of last build |
| Internal pentest report produced; findings remediated                      | Document tracking lives in `docs/operations/pentest-report.md` (initial baseline) |
| Secrets rotation automated and verified                                    | Agent certs auto-renewed on heartbeat; `secrets.Service.Put` supports rotate-in-place |

## Defense-in-depth summary

- API gateway: JWT validation + tenant middleware + RBAC + MFA gating + rate limit + security headers
- Scope Guard: every scan evaluated against 9-decision matrix
- Agent: signed-job verifier + local policy enforcer + emergency stop
- Evidence: AES-256-GCM at rest + signed URLs (5m TTL) + MFA-gated download
- Audit: hash-chained immutable log with periodic verification endpoint

## Key files

- `backend/internal/middleware/middleware.go`
- `backend/internal/secrets/secrets.go`
- `backend/internal/auth/jwt.go`
- `agent/internal/verifier/verifier.go`
