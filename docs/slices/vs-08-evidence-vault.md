# VS-08 · Evidence Vault

| Acceptance Criterion                                                            | Implementation |
|---------------------------------------------------------------------------------|----------------|
| Evidence stored encrypted at rest; plaintext never written to disk              | `backend/internal/evidence/vault.go` `Vault.encrypt` AES-256-GCM with random nonce + master key from env |
| Signed download URLs expire within 5 minutes                                    | `Vault.urlTTL` defaults to 5m via `WithURLTTL`; `signRef` HMAC-SHA256 over `id\|exp` |
| Every download generates an `evidence_access_logs` entry with user, timestamp, IP | `Vault.Read` calls `logAccess` and `audit.Record(EventEvidenceDownloaded)` |
| Cross-tenant evidence access blocked at API layer                                | `evidence_id`-based lookup checks `tenant_id` (joined via finding); MFA + `download_evidence` permission required |
| Immutable retention flag prevents deletion until period expires                  | `finding_evidence.immutable_until` column; cleanup workers respect it (HS-02) |
| Checksum mismatch on upload rejected and logged                                  | `Vault.Record` computes SHA-256 and stores in DB; production uploader verifies before commit |

## Key files

- `backend/migrations/0007_findings_evidence.up.sql` (`finding_evidence`, `evidence_access_logs`)
- `backend/internal/evidence/vault.go` + `evidence/sign.go` + `evidence/vault_test.go`
- `frontend/src/pages/EvidenceVault.tsx`
