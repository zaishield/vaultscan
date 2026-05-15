# KEK / DEK Rotation

Owns: platform_security_admin + CISO.

VAULTSCAN uses envelope encryption (VS-08):

- **KEK** (Key Encryption Key) — `VAULTSCAN_EVIDENCE_MASTER_KEY` —
  wraps every per-tenant DEK + the scanner pull-credentials KEK +
  the JWT-signing-key private halves + the TOTP shared secrets.
- **DEK** (Data Encryption Key) — `tenant_data_keys.wrapped_key` —
  the actual key the evidence vault uses to seal objects.

Two rotation paths:

| Scenario | Procedure | Customer impact |
|---|---|---|
| Scheduled DEK rotation (yearly) | §DEKRotation per tenant | Zero |
| Scheduled KEK rotation (yearly) | §KEKRotation | Brief read-only window |
| Suspected KEK compromise | §Emergency | Full read-only freeze + key replacement |

## Pre-conditions

- [ ] Co-signer is on the line.
- [ ] You have a fresh 32-byte key from the platform HSM (or a
      generated `openssl rand -base64 32` for non-HSM dev/staging).
- [ ] You have `psql` superuser access (rotation touches the
      `tenant_data_keys` + `jwt_signing_keys` + `user_mfa` tables).
- [ ] Customer notification has been sent (24h notice for scheduled
      rotation; immediate for emergency).

## §DEKRotation — yearly tenant DEK rotation

Each tenant has a versioned DEK in `tenant_data_keys`. Rotation:

```bash
# 1. Generate a new DEK and insert as the latest version.
curl -X POST https://api/api/v1/tenants/<tenant>/data-key/rotate \
  -H "Authorization: Bearer $TOKEN"
# → {"new_key_version": 2}
```

This:
- Adds a new row with `key_version=N+1, retired_at=NULL`.
- Existing evidence stays sealed under the OLD version
  (`encryption_key_version` on each `finding_evidence` row pins it).
- New evidence uploads use the new version.

**The old key is NOT deleted.** Old evidence remains decryptable
forever (the vault picks the right version via
`tenantKeyByVersion`). Only retire the old version when every
object sealed under it has been re-sealed under the new one —
which is a separate "re-encryption sweep" beyond the scope of a
scheduled rotation.

**Verification**:
```sql
SELECT key_version, retired_at FROM tenant_data_keys
 WHERE tenant_id = '<uuid>' ORDER BY key_version;
```
Two rows: old (`retired_at IS NULL`), new (`retired_at IS NULL`).
The new one is the highest version → it's the active one.

**Roll back**: simply retire the new version:
`UPDATE tenant_data_keys SET retired_at=now() WHERE tenant_id=<t>
AND key_version=<new-version>` — new uploads then fall back to
the previous-highest active version.

## §KEKRotation — yearly platform KEK rotation

This affects EVERY tenant DEK + EVERY JWT private key + EVERY MFA
secret. Procedure:

1. **Notify**: 24h status-page notice that an unspecified
   maintenance window is upcoming.
2. **Generate** the new KEK out-of-band: HSM in production, sealed
   envelope in cold storage; key must never have touched a
   network-connected machine.
3. **Stage** the new KEK alongside the old as an env var
   `VAULTSCAN_EVIDENCE_MASTER_KEY_NEXT=<base64>`.
4. **Deploy** a special "dual-KEK" build that knows both keys
   (the wrap helpers try `_NEXT` first, fall back to the original).
   This build is on a feature branch; tag + sign before deploy.
5. **Run the rewrap script**:
   ```bash
   ./tools/scripts/kek-rewrap.sh --from-env VAULTSCAN_EVIDENCE_MASTER_KEY \
                                  --to-env   VAULTSCAN_EVIDENCE_MASTER_KEY_NEXT
   ```
   The script:
   - Unwraps every `tenant_data_keys.wrapped_key` under the old KEK,
     re-wraps under the new KEK, writes the row back.
   - Same for `jwt_signing_keys.private_key_encrypted`.
   - Same for `user_mfa.totp_secret_encrypted`.
   Each rewrap is atomic at the row level (a transaction per row);
   a mid-script failure leaves a mix of old + new but no corruption
   — the dual-KEK build handles both.
6. **Promote**: rename `_NEXT` → primary in the env. Drop the old
   KEK from the env entirely.
7. **Deploy** the production build (single-KEK).
8. **Verify** end-to-end:
   - `curl /api/v1/audit/verify-deep` → first_bad_id = 0
   - A test tenant's evidence upload → integrity verify passes
   - A login → MFA verify succeeds
   - Token rotation: `POST /api/v1/auth/jwt-keys/rotate` succeeds

## §Emergency — suspected KEK compromise

The compromised KEK is in attacker hands. They can decrypt every
sealed thing in the database. Procedure:

1. **Within 1h**: Enable maintenance mode for ALL writes
   (`PUT /api/v1/platform/maintenance enabled=true`).
2. **Within 4h**: Generate a new KEK (offline / HSM).
3. **Within 8h**: Run the rewrap script (§KEKRotation step 5).
   The window matters because the attacker could be doing the
   same — race to re-wrap before they can stage their version.
4. **Notify customers** of the suspected compromise per the
   incident response runbook. Regulator notification per
   jurisdiction (GDPR 72h, etc.).
5. **Force MFA re-enrolment** for every active user:
   ```sql
   UPDATE users SET mfa_status='required' WHERE mfa_status='enrolled';
   ```
   The next login forces a re-enrol that replaces every TOTP
   secret. (The old TOTP secrets are technically still valid for
   the next 30s windows; combine with token revocation for full
   cleanup.)
6. **Revoke all active JWTs**:
   ```bash
   curl -X POST https://api/api/v1/auth/jwt-keys/rotate
   curl -X POST https://api/api/v1/auth/jwt-keys/rotate  # twice
   psql -c "UPDATE jwt_signing_keys SET status='retired'
            WHERE status='verify_only'"
   ```
   Two rotations + verify_only retirement forces every
   in-flight token to fail.
7. **PIR within 48h**, regulator response within mandated window.

## Audit footer

KEK rotation MUST write the following audit_logs rows:
- `crypto.kek.rotation_started`
- `crypto.kek.rewrap_completed` (with row counts)
- `crypto.kek.rotation_promoted`
- `crypto.kek.rotation_complete`

DEK rotation per tenant:
- `crypto.dek.rotated` (one per tenant)

Emergency adds:
- `crypto.kek.compromise_declared`
- `crypto.kek.force_remediation_complete`

Both operator actor_ids on every row.
