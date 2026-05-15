# VS-09 · Retesting Workflow

| Acceptance Criterion                                                                | Implementation |
|-------------------------------------------------------------------------------------|----------------|
| Retest scan scoped strictly to original endpoint; broader scan not permitted        | `backend/internal/retesting/service.go` `Request` queues a retest tied to `finding_id`; downstream scan must reuse the affected endpoint |
| Retest Failed transitions finding back to Open                                       | `RecordResult` calls `findings.Transition` → `retest_failed`; `AllowedTransitions["retest_failed"] = setOf("open")` |
| Retest evidence stored in vault and linked to finding's Retest History               | `retest_evidence` table joins `retest_results` + `finding_evidence` |
| Retest request logged as audit event                                                 | `audit.Record(EventRetestRequested)` and `EventRetestPassed`/`EventRetestFailed` |
| Pentester can execute; Analyst cannot trigger scan execution                         | API: `POST /api/v1/retests/{id}/result` requires `execute_retest` permission, only granted to MSSP Analyst (no), Pentester (yes), Engagement Manager (no - only request) |

## Key files

- `backend/migrations/0008_retesting_reporting.up.sql`
- `backend/internal/retesting/service.go`
- `frontend/src/pages/Retesting.tsx`
