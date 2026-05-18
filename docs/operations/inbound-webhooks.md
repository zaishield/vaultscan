# Inbound Webhook Verification Runbook

How partner systems POST callbacks into VaultScan and how we verify
those calls.

## Endpoint

```
POST /api/v1/integrations/{integration_id}/inbound
```

Unauthenticated (no bearer token); the request authenticates via an
HMAC-SHA256 signature derived from a per-integration shared secret.
Operators rotate the secret via:

```
PUT /api/v1/integrations/{integration_id}/signing-secret
```

(operator-only, `manage_integrations` permission).

## Wire format

Headers the partner MUST send:

```
X-VaultScan-Timestamp: 1715472000          # unix epoch seconds
X-VaultScan-Signature: 7b1d3a5f...         # hex HMAC-SHA256
                                           # or "sha256=<hex>"
                                           # or Stripe-style:
                                           #   t=1715472000,v1=<hex>
```

Signed payload is `"<timestamp>" || "." || <raw_body_bytes>`. The
verifier:

1. Rejects signatures more than 5 minutes from `now` (replay window)
2. Compares the supplied signature against the stored secret using
   `hmac.Equal` (constant-time)
3. Writes an `integration_inbound_log` row (verified true/false,
   rejection_code, source_ip, body_sha256) regardless of outcome

## Production posture

`VAULTSCAN_REQUIRE_INBOUND_SIG=true` is the production default. With
this set, an integration that has no `signing_secret_encrypted` row
gets a `403 secret_not_configured` and the call is dropped. Operators
MUST populate the secret before pointing the partner at the endpoint.

Setting `VAULTSCAN_REQUIRE_INBOUND_SIG=false` (dev / migration only)
lets pre-secret integrations receive callbacks without verification —
useful during a partner's initial wiring while you wait for them to
copy the secret.

## Rotating a secret

Generate a high-entropy secret (32+ bytes random base64), send it
through your normal partner secret-share channel, then push to
VaultScan:

```bash
curl -X PUT "https://api.vaultscan.zaishield.com/api/v1/integrations/${IID}/signing-secret" \
  -H "Authorization: Bearer ${OPERATOR_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"secret": "..."}'
```

The secret is wrapped under the evidence vault DEK before storage.
Clearing the secret (empty string) DISABLES verification for that
integration and is logged in the response body.

## Forensics — investigating bad callers

`integration_inbound_log` records every callback. To find rejected
deliveries in the last hour:

```sql
SELECT received_at, source_ip, rejection_code, body_sha256
  FROM integration_inbound_log
 WHERE integration_id = '<iid>'
   AND verified = false
   AND received_at > now() - INTERVAL '1 hour'
 ORDER BY received_at DESC;
```

Rejection codes:

| Code                  | Meaning                                 |
| --------------------- | --------------------------------------- |
| missing_signature     | No X-VaultScan-Signature header         |
| skew                  | Timestamp outside 5-minute window       |
| mismatch              | HMAC didn't match stored secret         |
| no_secret             | Integration has no secret configured    |
| no_unwrap             | Vault unavailable to decrypt secret     |
| unwrap_failed         | Vault decrypt failed (key version drift) |
| unsupported_algo      | signing_algorithm column is exotic      |
| lookup_failed         | DB error during secret lookup           |

## Integration test

```bash
SECRET="topsecret"
TS=$(date +%s)
BODY='{"hello":"world"}'
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -X POST "https://api.vaultscan.zaishield.com/api/v1/integrations/${IID}/inbound" \
  -H "X-VaultScan-Timestamp: $TS" \
  -H "X-VaultScan-Signature: $SIG" \
  -H "Content-Type: application/json" \
  -d "$BODY"
# expect: 202 Accepted
```

A 401 / 403 means the signature didn't verify; check `rejection_code`
in the log table.
