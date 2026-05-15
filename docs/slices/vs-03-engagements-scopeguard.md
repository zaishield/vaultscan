# VS-03 · Engagement & Scope Guard

| Acceptance Criterion                                                                  | Implementation |
|---------------------------------------------------------------------------------------|----------------|
| All 9 Scope Guard output states triggerable and verified via test                     | `backend/internal/scopeguard/scopeguard.go` (`Decision*` constants); unit tests `backend/internal/scopeguard/scopeguard_test.go` |
| Scan submitted for expired engagement is blocked with correct reason                  | `Service.Evaluate` returns `DecisionBlockedExpired` when status≠active or window violated |
| Scan without authorization document is blocked                                        | `Evaluate` checks `authorization_documents` row count > 0 → `DecisionBlockedMissingAuth` |
| Every Scope Guard decision written immutably to `scope_decision_logs`                 | `Service.log()` inserts on every evaluation |
| Approval requires `approve_scope` permission; unapproved scope cannot start a scan    | API route `POST /api/v1/scope/{id}/approve` wrapped in `RequirePermission("approve_scope")`; orchestrator only matches approved targets |
| Authorization documents stored encrypted and linked to engagement                     | `backend/internal/authdocs/service.go` writes via `evidence.Vault.Put` (AES-256-GCM); SHA256 stored in DB |

## Decision matrix coverage

```
DecisionApproved
DecisionBlockedOutOfScope
DecisionBlockedMissingAuth
DecisionBlockedExpired
DecisionBlockedTimeWindow
DecisionBlockedWrongAgent
DecisionBlockedWrongTenant
DecisionBlockedRateLimit
DecisionRequiresManualApproval
```

## Key files

- `backend/migrations/0003_engagements_scope.up.sql`
- `backend/internal/engagements/service.go`
- `backend/internal/scopeguard/scopeguard.go` + `scopeguard_test.go`
- `backend/internal/authdocs/service.go`
- `frontend/src/pages/{Engagements,Scope}.tsx`
