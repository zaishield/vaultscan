# VS-07 · Findings Engine

| Acceptance Criterion                                                                                  | Implementation |
|-------------------------------------------------------------------------------------------------------|----------------|
| Raw Nmap, ZAP, Nuclei, OpenVAS, testssl.sh outputs each parsed and produce normalized findings        | `backend/internal/parsers/parsers.go` exposes `Registry["nmap"]…["mobsf"]`; tests in `parsers_test.go` |
| Duplicate findings from two scanners for same CVE on same asset deduplicated to one record            | `findings.dedupFingerprint` uses 9-field key (Blueprint §17.4); UNIQUE index on `(tenant_id, dedup_fingerprint)` triggers the upsert path |
| All 11 finding lifecycle statuses reachable via valid transitions                                     | `findings.AllowedTransitions` map; tested in `findings_test.go` |
| Finding detail page displays all 11 required sections                                                 | `frontend/src/pages/Findings.tsx` `Section` blocks: Summary, Affected Asset, Business Impact, Technical Details, Evidence, Remediation, References, Status History, Comments, Retest History, Audit Trail |
| CVSS score, CWE, CVE populated for findings where source provides them                                | All parsers populate them; canonical model in `models.Finding` |

## Key files

- `backend/migrations/0007_findings_evidence.up.sql`
- `backend/internal/findings/service.go` + `findings_test.go`
- `backend/internal/parsers/parsers.go` + `parsers_test.go` (13 parsers)
- `frontend/src/pages/Findings.tsx`
