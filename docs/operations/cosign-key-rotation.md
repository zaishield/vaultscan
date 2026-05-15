# Cosign Trust-Key Rotation

Owns: platform_security_admin.

Cosign-signed scanner images flow through the VS-05 verifier:
`scanner.Registry.VerifyImage` rejects any image whose signature
doesn't verify under an active trusted key. This runbook rotates
that trust key safely — old images keep working until they're
re-signed under the new key, then the old key is retired.

## Pre-conditions

- [ ] You have the new keypair in a secure offline channel. Generate
      with `cosign generate-key-pair` against a hardware key (YubiHSM
      preferred) — the private half never lives on a build server.
- [ ] You have `db` write access AND a co-signer (this rotation
      affects every scanner workload).
- [ ] All in-flight scan jobs are drained or you've accepted that
      they'll fail signature verification mid-flight and retry.

## Step 1 — Add the new trust key as inactive

```sql
INSERT INTO cosign_trusted_keys
  (key_id, public_key_pem, key_type, status, not_after)
VALUES (
  'cosign-2026-q3',
  '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  'ecdsa-p256',
  'inactive',        -- inactive: verifier rejects sigs under this key
  '2027-09-01'
);
```

The cosign verifier (`backend/internal/cosign/cosign.go`) ignores
`status='inactive'` rows so this is safe to insert at any time.

**Verification**: `SELECT key_id, status FROM cosign_trusted_keys
WHERE key_id='cosign-2026-q3'` → `inactive`.

## Step 2 — Re-sign every active scanner image with the new key

In the image-pipeline CI:

```bash
for tool in $(ls tools/scanner-images); do
  cosign sign \
    --key new-cosign.key \
    --recursive \
    registry.zaishield.com/vaultscan/scanners/${tool}:latest
done
```

The new signature lives alongside the old one in the registry; both
verify independently.

## Step 3 — Update `scanner_image_registry` with the new sig bundle

```bash
# The image-pipeline writes this row automatically via the
# scanner-image-release runbook, but if you're rotating manually:
psql <<'SQL'
UPDATE scanner_image_registry
   SET cosign_signature = '<base64 sig from cosign verify --output-format=text>',
       cosign_payload   = '<base64 cosign payload>',
       cosign_key_id    = 'cosign-2026-q3'
 WHERE tool = '<tool>';
SQL
```

**Verification**: A test scan against a tenant's staging engagement
completes with `decision = accepted` in `cosign_verifications`.

## Step 4 — Promote the new key to active

```sql
BEGIN;
UPDATE cosign_trusted_keys SET status='verify_only' WHERE status='active';
UPDATE cosign_trusted_keys SET status='active' WHERE key_id='cosign-2026-q3';
COMMIT;
```

Two-person sign-off here — both operators in the SQL session
simultaneously, both confirm before COMMIT.

**Verification**: The scanner-worker's first verify after this hits
the new key. Watch `vaultscan_audit_chain_breaks_total` and
`vaultscan_scan_jobs_completed_total{status="failed"}` for 30
minutes — any spike means a tool image still carries only the old
signature.

## Step 5 — Retire the old key

After the access-window has fully elapsed (typically 24h to be sure
every cached signature has been re-verified at least once):

```sql
UPDATE cosign_trusted_keys
   SET status='retired', not_after=now()
 WHERE key_id='<old-kid>' AND status='verify_only';
```

**Verification**: `vaultscan_scan_jobs_completed_total{status="failed"}`
rate stays at baseline for 1h after retirement. If it spikes, roll
back the retirement via `UPDATE ... SET status='verify_only'`.

## §Emergency — suspected private-key compromise

Skip steps 2 + 4 caution; act in this order:

1. **Immediately** flip the suspected key to `revoked`:
   ```sql
   UPDATE cosign_trusted_keys SET status='revoked' WHERE key_id='<kid>';
   ```
2. Refuse all running scans:
   `POST /api/v1/scans/emergency-stop` with `scope: all`.
3. Re-sign all active images with a fresh, never-seen-online key
   (per step 2).
4. Insert the new key as `active` (step 4) AND audit every
   `cosign_verifications` row in the last 90 days for `decision`
   under the compromised key.
5. Notify CISO + customers per the incident-response runbook.

## Audit footer

Each rotation writes 5 `audit_logs` rows: `cosign.key.added`,
`cosign.signatures.bulk_published`, `cosign.key.promoted`,
`cosign.key.retired`, and (if applicable) `cosign.key.revoked`.
Both operators' actor_ids on every row.
