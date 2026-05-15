# JWT Signing Key Rotation

Owns: platform_security_admin.

The HS-01 deepening replaced the static HMAC secret with versioned
RSA keypairs in `jwt_signing_keys`. Rotation is hot — no token is
invalidated mid-flight as long as you respect the grace window.

## Pre-conditions

- [ ] You have a JWT with `create_tenant` permission and MFA
      verified (the rotation endpoint requires both).
- [ ] You know the access-token max lifespan
      (`cfg.AccessTokenLifespan`, default 15 minutes). The grace
      window after rotation must be at least this long.

## Step 1 — Mint a new active key

```bash
curl -X POST https://api/api/v1/auth/jwt-keys/rotate \
  -H "Authorization: Bearer $TOKEN"
# → {"status":"rotated","new_kid":"vs-a1b2c3d4e5f6g7h8"}
```

Atomically inside `KeyManager.Rotate`:
1. The current `status='active'` row flips to `verify_only`.
2. A fresh RSA-2048 keypair is generated, wrapped under the KEK,
   inserted as `status='active'`.

In-flight tokens signed by the old kid keep verifying because the
verify path accepts both `active` and `verify_only` rows. New
tokens are signed by the new kid (the header carries it).

**Verification**:
```sql
SELECT kid, status FROM jwt_signing_keys ORDER BY created_at DESC LIMIT 5;
```
The top row has `status='active'`; the second has `status='verify_only'`.

`/.well-known/jwks.json` exposes both:
```bash
curl https://api/.well-known/jwks.json | jq '.keys[].kid'
# "vs-a1b2c3d4e5f6g7h8"
# "vs-prev1234567890ab"
```

## Step 2 — Wait the grace window

Whatever your access-token max lifespan is, wait at least that long
before retiring the old key. Default Keycloak config in
`infra/keycloak/vaultscan-realm.json` is `accessTokenLifespan: 900`
(15 minutes) — wait 20 minutes to be safe.

During the wait window:
- New tokens sign with new kid ✓
- Old tokens still verify ✓
- The cron-runner's `audit_verify_deep` job keeps watching the
  chain.

## Step 3 — Retire the old key

The cron-runner promotes `verify_only` → `retired` automatically
once the row is older than the configured grace
(`RetireOld(gracePeriod)` — set to 2× access-token lifespan by
default). For a manual retire:

```sql
UPDATE jwt_signing_keys
   SET status='retired', retired_at=now()
 WHERE kid='<old-kid>' AND status='verify_only';
```

**Verification**: Trying to verify an old-kid token now returns
`jwks: kid not known or retired`. Production fleets should be fully
on new-kid tokens by this point so this is a quiet no-op for
legitimate traffic.

**Roll back**: `UPDATE ... SET status='verify_only'` to re-enable
the kid. This is the standard "I retired too aggressively" recovery
— Postgres holds the data forever, only the status changes.

## §Emergency — suspected private-key exposure

If you suspect the active signing private key has been exposed:

1. **Within 5 min**: Rotate twice in quick succession. The second
   rotation moves the suspect key past `verify_only` into the
   "about to be retired" pool. Don't wait the grace window.
2. **Force retire** every non-current key:
   ```sql
   UPDATE jwt_signing_keys
      SET status='retired', retired_at=now()
    WHERE status='verify_only';
   ```
3. Every in-flight token now fails. Customers re-authenticate.
4. PIR per the incident-response runbook.

## Schedule

- **Routine**: quarterly. Calendar event on the security team's
  shared calendar; cron-runner emits a metric
  (`vaultscan_jwt_active_key_age_seconds`) the Prometheus alertmanager
  fires on > 100 days.
- **Forced** (Keycloak realm export rotation): every Keycloak realm
  export must follow with a JWT rotation so the realm's signing key
  doesn't outlast the platform's.

## Audit footer

- `auth.jwt.rotated` (step 1, payload includes `old_kid` + `new_kid`)
- `auth.jwt.retired`  (step 3)
- `auth.jwt.emergency_force_remediation` (emergency path)
