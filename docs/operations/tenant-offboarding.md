# Tenant Offboarding / GDPR Erasure

Owns: legal + customer-success; executed by platform_security_admin.

Used when:
1. A tenant cancels their subscription, or
2. A GDPR Article 17 ("right to erasure") request is received, or
3. A regulatory order requires data deletion.

Erasure is **destructive and irreversible** — two-person sign-off
required. Audit-log rows referencing the tenant are kept (audit
immutability trumps erasure in most regulatory carve-outs); the
runbook records what was kept and why.

## Pre-conditions

- [ ] You have a written, signed request (PDF in legal's vault).
- [ ] Engagement under the tenant is in status `closed` OR the
      customer has explicitly waived the close-engagement
      requirement.
- [ ] Co-signer is available and in the same channel.
- [ ] Break-glass token with `tenant.delete` permission issued
      for the operator's shift (HS-05).

## Step 0 — Snapshot before destruction

```bash
# Take a snapshot of every tenant-scoped row first. Even when
# the request is for erasure, you need a snapshot for the legal
# response window (typically 30 days for the regulator to verify
# completion).

./tools/scripts/tenant-snapshot.sh --tenant-id <uuid> \
  --output s3://vaultscan-legal/<ticket>/<tenant>-pre-erasure.tar.gz \
  --encrypt-with-kek <legal-kek-arn>
```

The snapshot is encrypted under a **separate KEK** held by legal —
not the platform's KEK — so platform engineers can't reverse the
erasure from backups alone.

**Verification**: `aws s3 ls` shows the object exists + tag
`retention=legal-hold` is set.

## Step 1 — Disable tenant access

```bash
curl -X POST https://api/api/v1/tenants/<uuid>/suspend \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason":"erasure-request-<ticket>"}'
```

Every user under the tenant is logged out via the VS-01 token-
revocation flow. Agents continue running (we'll handle those next)
but new logins are blocked.

**Verification**: `SELECT status FROM tenants WHERE id=<uuid>`
→ `suspended`. `SELECT count(*) FROM token_revocations
WHERE issuer_user_id IN (SELECT id FROM users WHERE tenant_id=<uuid>)`
> 0.

## Step 2 — Revoke agent certs + uninstall agents

```bash
# Revoke certs first so the agent loses its ability to talk back.
psql -c "UPDATE agent_certificates SET revoked_at=now()
         WHERE agent_id IN (SELECT id FROM agents WHERE tenant_id='<uuid>')"

# Mark agents revoked so the registry stops accepting their handshakes.
psql -c "UPDATE agents SET status='revoked' WHERE tenant_id='<uuid>'"
```

Email the tenant's contact with the uninstall instructions
(packaged in the offboarding template).

**Verification**: `SELECT decision FROM agent_mtls_handshakes
WHERE agent_id IN (SELECT id FROM agents WHERE tenant_id='<uuid>')
ORDER BY occurred_at DESC LIMIT 1` → `rejected_revoked`.

## Step 3 — Delete tenant-scoped data

```bash
psql -h <prod-pg> -d vaultscan <<'SQL'
BEGIN;
-- The CASCADE chains catch most of this, but be explicit so the
-- DBA reviewer can read what's being deleted at each step.
DELETE FROM evidence_chain_of_custody
 WHERE evidence_id IN (SELECT id FROM finding_evidence WHERE tenant_id=:tenant);
DELETE FROM finding_evidence WHERE tenant_id=:tenant;
DELETE FROM retest_results
 WHERE retest_request_id IN (SELECT id FROM retest_requests
                              WHERE finding_id IN (SELECT id FROM findings WHERE tenant_id=:tenant));
DELETE FROM retest_requests
 WHERE finding_id IN (SELECT id FROM findings WHERE tenant_id=:tenant);
DELETE FROM finding_status_history
 WHERE finding_id IN (SELECT id FROM findings WHERE tenant_id=:tenant);
DELETE FROM findings WHERE tenant_id=:tenant;
DELETE FROM scan_jobs WHERE tenant_id=:tenant;
DELETE FROM asset_relationships
 WHERE parent_id IN (SELECT id FROM assets WHERE tenant_id=:tenant)
    OR child_id  IN (SELECT id FROM assets WHERE tenant_id=:tenant);
DELETE FROM assets WHERE tenant_id=:tenant;
DELETE FROM authorization_documents
 WHERE engagement_id IN (SELECT id FROM engagements WHERE tenant_id=:tenant);
DELETE FROM scope_targets
 WHERE engagement_id IN (SELECT id FROM engagements WHERE tenant_id=:tenant);
DELETE FROM engagements WHERE tenant_id=:tenant;
DELETE FROM user_mfa
 WHERE user_id IN (SELECT id FROM users WHERE tenant_id=:tenant);
DELETE FROM users WHERE tenant_id=:tenant;
DELETE FROM tenant_settings WHERE tenant_id=:tenant;
DELETE FROM tenant_data_keys WHERE tenant_id=:tenant;
DELETE FROM tenants WHERE id=:tenant;
COMMIT;
SQL
```

Run this **inside a transaction** with both operators reviewing the
`EXPLAIN` plan first. A typo here is unrecoverable.

**Verification**: `SELECT count(*) FROM tenants WHERE id=<uuid>` → 0.

## Step 4 — Purge evidence vault objects

Evidence storage is content-addressed. The DELETE in step 3 dropped
the metadata rows; the encrypted blobs still sit on disk. Purge:

```bash
./tools/scripts/evidence-purge.sh --tenant-id <uuid> --force
```

The script walks the tenant's storage prefix, deletes the blobs,
records a `evidence.purged_offboarding` event per object.

WORM-locked objects are an exception. If the customer explicitly
requests deletion of WORM objects, escalate to legal — WORM
generally outranks erasure requests.

**Verification**: `ls /var/lib/vaultscan-evidence/<uuid>` returns
empty (or refused — directory deleted). S3-backed deployments:
`aws s3 ls s3://<bucket>/<uuid>/` returns nothing.

## Step 5 — Rotate KEK references

The tenant's DEK is gone (deleted in step 3). If the platform KEK
was compromised in any way that affected this tenant, also rotate
the KEK now — see [kek-dek-rotation.md](kek-dek-rotation.md).

## Step 6 — Confirm to the requester

Reply within the GDPR window (1 month) with:
- Date of deletion
- Categories of data deleted
- Audit-row ids documenting the deletion
- Categories of data **retained** (audit logs, billing records as
  per the privacy policy) — required for transparency

## What we DO NOT delete

- `audit_logs` rows referencing the tenant. The hash chain makes
  deletion impossible without breaking integrity; legal carve-out
  in the privacy policy covers this.
- Aggregated, anonymised analytics counters (no PII content).
- Billing records under the financial-records retention window.

## Audit footer

Required entries:
- `tenant.snapshot_archived` (step 0)
- `tenant.suspended` (step 1)
- `agent.fleet_revoked` (step 2)
- `tenant.data_deleted` (step 3, with row counts in payload)
- `tenant.evidence_purged` (step 4)
- `tenant.erasure_complete` (step 6)

Each row must have BOTH operators' `actor_id`s in the payload.
