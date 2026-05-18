# Secret-rotation runbook

This runbook covers the four secrets the platform rotates on a
schedule or in response to suspected compromise:

1. **Evidence master KEK** — the AES-256-GCM key that wraps every
   tenant DEK.
2. **JWT signing key** — the RSA/EC key that signs platform-issued
   JWTs (auth.NewKeyManager).
3. **Integration signing secret** — the HMAC secret webhook
   senders use for inbound signature verification.
4. **Agent enrollment certificate** — the on-prem agent's
   mTLS identity (issued at provision time, rotated on demand).

Every rotation in this document has automated test coverage AND a
verify-it-worked step. Don't skip the verify.

---

## 1. Evidence master KEK rotation

### Why

SOC 2 CC6.7 expects key material to rotate on a documented schedule
(commonly 365 days for KEKs that wrap long-lived DEKs). The
platform supports rotation without re-encrypting every evidence
blob — only the per-tenant DEKs (one row each) get re-wrapped.

### When

- Scheduled: every 365 days.
- Unscheduled: any suspicion the old KEK material has been
  exposed (e.g., a compromised operator workstation that held a
  decrypted copy of the env file).

### Procedure

**Step 1 — generate new KEK material**

```bash
openssl rand -base64 32 | tr -d '\n' > /tmp/new-kek.b64
# 32 bytes (the AES-256 key size) — DO NOT trim or shorten.
```

Store the new key in your KMS / secret manager under a new
versioned name (e.g. `vaultscan/evidence-kek/v2`).

**Step 2 — restart the API + cron-runner in rotation mode**

Set the following env in your helm values (or whatever deployment
overlay you use) and roll the deployments:

```yaml
VAULTSCAN_EVIDENCE_MASTER_KEY: <new KEK base64>
VAULTSCAN_EVIDENCE_PREVIOUS_KEYS: <old KEK base64>   # comma-separated if multiple
VAULTSCAN_EVIDENCE_ACTIVE_KEK_ID: platform-master-v2
```

The wiring (in `backend/cmd/api/main.go` and `cron-runner/main.go`)
threads these into `evidence.NewVault` via `WithActiveKEKID` +
`WithPreviousMasterKeys`.

**Verify the rotation window is live:**

```bash
# Existing evidence must still decrypt — the active KEK can't,
# but the retired-KEK fallback kicks in for old rows.
curl -H "Authorization: Bearer $TOKEN" \
     "$API/api/v1/evidence/$KNOWN_OLD_EVIDENCE_ID/download" > /tmp/out.bin
sha256sum /tmp/out.bin   # must match the row's recorded sha256
```

**Step 3 — drain old rows**

Run the rewrap sweep via the operator API (`POST
/api/v1/platform/evidence/rewrap-tenant-deks` once it's wired) or
via a one-off Go program:

```go
v.RewrapTenantDEKsToActiveKEK(ctx, 100)  // batch size 100
```

Loop until both consecutive calls return `(rewrapped=0,
more=false)`. On a 10k-tenant deployment this typically converges
in 5-10 minutes; each row is a tiny CPU op (one AEAD unseal +
reseal).

**Step 4 — drop retired KEK from config**

After two consecutive sweeps report no work:

```yaml
VAULTSCAN_EVIDENCE_MASTER_KEY: <v2>
# VAULTSCAN_EVIDENCE_PREVIOUS_KEYS: REMOVED
VAULTSCAN_EVIDENCE_ACTIVE_KEK_ID: platform-master-v2
```

Roll the deployments. Confirm existing evidence still decrypts.

**Step 5 — destroy old KEK material**

In your KMS / secret manager, mark the v1 key as
`scheduled-for-deletion`. Wait 30 days (recovery buffer for an
unforeseen issue), then schedule actual deletion.

**Step 6 — verify**

```bash
# Every tenant_data_keys row should now carry kek_id=v2.
psql -c "SELECT kek_id, COUNT(*) FROM tenant_data_keys GROUP BY 1"
# Expect a single row: platform-master-v2 | <total>
```

### Failure modes

- **Sweep finds rows with unwrap_failed**: a row exists whose old
  KEK isn't in your previous-keys list. STOP. Add the missing
  key, re-run.
- **A user reports they can't download evidence**: roll back the
  drop-retired-KEK step. The retired key must remain configured
  until the sweep converges.

### Test coverage

`backend/test/integration/kek_rotation_test.go`:
- `TestKEKRotation_EndToEnd` — full rotate-and-drop drill
- `TestKEKRotation_RewrapIsIdempotent` — re-running converges to 0

---

## 2. JWT signing key rotation

### Why

JWT signing keys MUST rotate or expire. RFC 8725 §2.3 recommends
rotation on a 90-day schedule for production-grade APIs. Platform
JWTs are issued for human users + service accounts; an attacker
who gains the signing key can forge tokens with any identity.

### When

- Scheduled: every 90 days.
- Unscheduled: a HSM / KMS exposure event, an admin laptop
  compromise, or an inadvertent disclosure (e.g. key in a public
  git commit).

### Procedure

The platform's auth/jwks.go maintains an active key + a
verify-only history. Both are exposed via the public JWKS endpoint
so external token consumers (downstream services that validate our
JWTs) see both during a rotation window.

**Step 1 — trigger a rotation**

```bash
curl -X POST \
     -H "Authorization: Bearer $PLATFORM_ADMIN_TOKEN" \
     "$API/api/v1/auth/jwt-keys/rotate"
```

This generates a new RSA key in the DB (with status='active'),
demotes the previous active key to status='verify_only', and the
public JWKS endpoint immediately serves both.

**Step 2 — wait for token TTL**

The platform's JWT TTL is 1 hour by default. Wait ≥ 1 hour AFTER
the rotation so every token issued under the old key has expired.

```bash
curl "$API/.well-known/jwks.json" | jq '.keys[] | {kid, status}'
# Should show both keys during the wait window.
```

**Step 3 — retire the old key**

Old key transitions from `verify_only` to `retired` via the same
endpoint pattern. Retired keys are no longer published in the
JWKS document; downstream verifiers stop trusting them.

```bash
curl -X POST \
     -H "Authorization: Bearer $PLATFORM_ADMIN_TOKEN" \
     "$API/api/v1/auth/jwt-keys/$OLD_KID/retire"
```

### Failure modes

- **A downstream service reports auth failures during rotation**:
  it has cached the JWKS. Force a JWKS refresh on its side. We
  serve `Cache-Control: max-age=300`; a 5-min wait fixes most
  cases.
- **An emergency rotation needs to invalidate ALL tokens
  immediately**: the rotation alone doesn't do this — old tokens
  remain valid until expiry. Pair with `POST /api/v1/users/{id}/
  revoke-tokens` for every user, OR a global
  `POST /api/v1/platform/revoke-all-tokens` (use sparingly — it
  forces every user to re-log).

---

## 3. Integration signing secret rotation

### Why

Each inbound webhook integration carries an HMAC signing secret.
Rotation lets a customer change credentials without a service-
window outage.

### Procedure

The relevant endpoint is `PUT /api/v1/integrations/{integration_id}/
signing-secret`. The handler accepts:
- `{"secret":"new_value"}` — rotate to a new secret
- `{"secret":""}` — clear the secret (revert to "inbound HMAC
  verification disabled")

Old and new secrets are NOT both accepted simultaneously — the
swap is atomic. Coordinate with the upstream system that signs the
webhooks: pre-stage the new secret in their config, then call
this endpoint, then they switch their signer to the new secret.

### Failure modes

- **Inbound webhooks start failing with signature_mismatch**: the
  upstream system is still signing with the old secret. Roll the
  PUT back with the old value, coordinate the cutover, then
  re-PUT.

---

## 4. Agent enrollment certificate rotation

### Why

On-prem scanner agents authenticate to agent-gateway via mTLS.
Certs MUST rotate before they expire (default validity 90 days)
AND on demand if an agent host is compromised.

### Procedure

```bash
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     "$API/api/v1/agents/$AGENT_ID/rotate-cert"
```

The handler issues a fresh enrollment token + marks the agent's
current certificate as revoked. The agent's update channel
detects the rotation and submits a new CSR via the agent-gateway
enroll endpoint with the new token.

### Verification

```bash
psql -c "SELECT id, last_seen_at, status FROM agents WHERE id='$AGENT_ID'"
# status should be 'rotating' immediately, then 'active' once the
# agent re-enrolls (typically <60 seconds).
```

---

## Operator's general principles

- **Never rotate two secrets simultaneously**. Each rotation has
  its own verify step; collapsing them hides which one introduced
  a problem.
- **Always keep the retired material accessible for at least one
  full TTL** of whatever uses it. The platform's fallback paths
  assume this.
- **Test rotation against staging first**. The integration tests
  cover the happy path; staging exercises whatever's wired to
  your real KMS / IdP / webhooks.
- **Document the actual rotation** in your operator runbook /
  change calendar with: date, reason, rotated-from / rotated-to
  identifiers, and the verify-it-worked check.
