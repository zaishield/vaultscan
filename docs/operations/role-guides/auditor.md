# External Auditor guide

**Primary objective:** evidence the customer's tenant against the
contracted framework(s). Read-only access; the platform produces
the artifacts you need.

This is for the auditor's individual reviewer account — usually
provisioned by the customer's tenant admin with the `auditor` role.

## What the role lets you do

| Capability | Endpoint |
| --- | --- |
| Read findings (current + historical) | `GET /api/v1/findings` |
| Read evidence chain-of-custody | `GET /api/v1/findings/{id}/evidence/chain` |
| Verify audit-chain integrity | `POST /api/v1/audit/verify` + `/verify-deep` |
| Export audit log (NDJSON / CSV) | `GET /api/v1/audit/export` |
| Read compliance evidence per framework | `GET /api/v1/compliance/{framework}/engagements/{id}` |
| Read tenant residency history | `GET /api/v1/tenants/{id}/residency-history` |
| Read scan history + tools used | `GET /api/v1/scans` + `/{id}` |
| Read all engagement scope + authorization documents | `GET /api/v1/engagements/{id}` |

## What you CANNOT do

| Restricted | Why |
| --- | --- |
| See another tenant | Multi-tenant isolation (RLS-enforced) |
| Mutate ANYTHING | Read-only role |
| See cryptographic key material | KMS-protected; you see metadata only |
| See raw evidence-blob contents | You see hash + chain proof; binary download requires `download_evidence` (separate grant) |
| See user passwords | None stored (IdP-only) |

## Common workflows

### Walking a finding's chain-of-custody

```bash
JWT=<your-auditor-jwt>
TENANT=<customer-tenant-id>
FINDING=<finding-id>

curl -s "https://api.<env>/api/v1/findings/$FINDING/evidence/chain" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" | jq
```

Returns the ordered event log:
```json
[
  {"event":"ingested",         "at":"...", "actor":"system",     "details":{"scanner":"nmap"}},
  {"event":"normalized",       "at":"...", "actor":"system",     "details":{}},
  {"event":"triaged",          "at":"...", "actor":"<user>",     "details":{"verdict":"true_positive"}},
  {"event":"assigned",         "at":"...", "actor":"<user>",     "details":{"assignee":"<user2>"}},
  {"event":"remediated",       "at":"...", "actor":"<user2>",    "details":{"note":"patched"}},
  {"event":"retest_passed",    "at":"...", "actor":"system",     "details":{"scan_id":"..."}},
  {"event":"closed",           "at":"...", "actor":"<user>",     "details":{}},
  {"event":"integrity_verified","at":"...", "actor":"system",    "details":{"hash":"..."}},
]
```

Each row is hash-chained to the previous, and the chain root anchors
into the platform-wide `audit_logs` chain.

### Verifying the audit chain hasn't been tampered

```bash
curl -X POST "https://api.<env>/api/v1/audit/verify-deep" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" | jq
```

Returns:
```json
{
  "chain_integrity_ok": true,
  "first_bad_id": null,
  "verified_at": "2026-05-18T15:00:00Z",
  "rows_walked": 12453,
  "tsa_anchors_verified": 28
}
```

Any `chain_integrity_ok=false` is a SOC2-grade incident. Document.

### Exporting the audit log for your working papers

```bash
# NDJSON, last 12 months:
curl -s "https://api.<env>/api/v1/audit/export?from=2025-05-18T00:00:00Z" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -o audit-export-$(date +%F).ndjson

# CSV:
curl -s "https://api.<env>/api/v1/audit/export?from=2025-05-18T00:00:00Z&format=csv" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -o audit-export-$(date +%F).csv
```

The platform applies row + wall-clock bounds; if you hit the cap
you'll see a `_truncated` field at the end of the stream. Paginate
via `?from=<last-occurred-at>` to continue.

### Reading the compliance evidence pack

```bash
# Per framework, per engagement, formatted as Markdown:
curl -s "https://api.<env>/api/v1/compliance/soc2/engagements/$ENG_ID.md" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  > soc2-$(date +%F).md
```

Contents:
- Engagement scope + authorization documents (with SHA-256)
- Per-control verdict + supporting query
- Sample evidence rows
- Chain-of-custody for each finding referenced

### Spot-checking residency

```bash
curl -s "https://api.<env>/api/v1/tenants/$TENANT/residency-history" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" | jq
```

Returns the full history of `data_region` pins on the tenant: who
changed it, when, why.

## Independence + integrity safeguards

The platform is designed to make tampering visible:

1. **Hash chain** on every audit row. A modified row breaks the
   chain at + everywhere after that row. `verify-deep` finds it.
2. **TSA anchor** every 24h. The `audit_archive_runs` table records
   the RFC 3161 timestamp token + hash. Tampering before the
   anchor would require also forging the TSA's signature.
3. **Cross-tenant RLS**. You CANNOT see another tenant by
   accident or by adversarial intent. RLS test:
   `backend/test/integration/rls_isolation_test.go`.
4. **Encrypted-at-rest evidence**. The platform stores evidence
   ciphertext + the per-tenant DEK reference. You see the metadata
   + hashes; binary contents require a separate audited download.
5. **Engineering-side audit**. Every action a VaultScan staff
   member takes is audited under their identity, not "system".
   `audit_logs WHERE actor_email LIKE '%@zaishield.com'` returns
   only the rows scoped to your tenant (RLS).

## What you produce

Typical audit deliverables:

| Deliverable | Source |
| --- | --- |
| Per-control evidence-of-controls | `/compliance/<framework>/engagements/<id>.md` |
| Audit log sample (full record set on request) | `/audit/export` NDJSON |
| Chain-of-custody for each tested finding | `/findings/<id>/evidence/chain` |
| Encryption attestation | screenshot of `tenant_data_keys` versioning + rotation history |
| Backup + DR attestation | from VaultScan support: latest `dr-drill.sh` run output |
| Pentest attestation | from VaultScan support: latest `pentest-engagement-runbook.md` report |
| Sub-processor list | VaultScan DPA / DPA addendum |

## Limitations (be honest with the customer)

The platform evidences technical controls. Organisational controls
(policy existence, training, vendor management) the customer
evidences separately. The platform's `data-classification.md` and
`threat-model.md` are evidence that POLICY exists; your job is to
verify the customer FOLLOWS them.

## When to escalate

If you find:
- Audit chain break → notify the customer's CISO + your engagement
  partner; this is reportable
- Cross-tenant data exposure → STOP testing and notify both your
  partner AND VaultScan security immediately
- Evidence-integrity failure (`verify-deep` flags rows) → document
  + request VaultScan engineering investigation
- Compliance evidence missing for >5% of controls → audit qualification

## Related

- `compliance-officer.md` — customer-side compliance role
- `threat-model.md` — what the platform threat-modelled
- `data-classification.md` — data sensitivity matrix
- `gdpr-erasure.md` — Article 17 procedure
- `inbound-webhooks.md` — webhook integrity model
