# Integrator guide

**Primary objective:** build on the VaultScan API — push events
INTO the platform, consume events OUT of it, or build a customer-
facing extension.

## API contract

OpenAPI 3.1 spec: `docs/api/openapi.yaml` (~176 paths, auto-
generated + hand-deepened for the customer-facing surface).

Generate a client SDK with [openapi-generator](https://openapi-generator.tech/):

```bash
# Go SDK:
openapi-generator-cli generate -i docs/api/openapi.yaml -g go -o sdk/go

# TypeScript SDK:
openapi-generator-cli generate -i docs/api/openapi.yaml -g typescript-fetch -o sdk/typescript

# Python SDK:
openapi-generator-cli generate -i docs/api/openapi.yaml -g python -o sdk/python
```

The platform does NOT yet ship pre-generated SDKs. The spec is the
source of truth.

## Authentication

Three options:

### 1. OAuth-style bearer JWT (recommended)

Get a token from the customer's IdP (via OIDC). The platform
verifies the JWT against the customer's published JWKS.

```http
GET /api/v1/findings HTTP/1.1
Host: api.<env>
Authorization: Bearer <jwt>
X-Tenant-Id: <tenant-uuid>
```

### 2. API key (for machine-to-machine)

The customer's admin creates an API key for your integration via
the portal. Treat it like a JWT: send in `Authorization: Bearer`.

API keys are bcrypt-hashed at rest, scoped to a single tenant, and
revocable via:
```bash
curl -X DELETE "https://api.<env>/api/v1/api-keys/<id>" ...
```

### 3. HMAC-signed inbound webhook (events going INTO the platform)

For your system to push events to the platform without holding a
JWT, the customer provisions an "inbound webhook" integration. They
share an HMAC secret with you. You send:

```http
POST /api/v1/integrations/{id}/inbound HTTP/1.1
Host: api.<env>
X-Vaultscan-Timestamp: 1716035000
X-Vaultscan-Signature: sha256=<hex>
Content-Type: application/json

{"event":"...","payload":{...}}
```

Where `<hex>` is `HMAC-SHA256(secret, "<timestamp>.<body>")`. The
platform refuses signatures older than 5 minutes (replay protection).

See `inbound-webhooks.md` for the full reference + rotation procedure.

## Outbound webhooks (events coming OUT of the platform)

When a customer-relevant event happens (scan complete, finding
created, agent disconnected, etc.) the platform POSTs to your
integration's configured URL.

### Event types

Walk `backend/internal/eventbus/eventbus.go` `AllEventTypes()` for
the canonical list. Categories:

| Category | Examples |
| --- | --- |
| Tenant / Engagement | `tenant.created`, `engagement.activated`, `engagement.paused` |
| Scan | `scan.queued`, `scan.dispatched`, `scan.completed`, `scan.failed` |
| Finding | `finding.created`, `finding.triaged`, `finding.remediated`, `finding.retest_*` |
| Asset | `asset.discovered`, `asset.deleted` |
| Agent | `agent.enrolled`, `agent.disconnected`, `agent.cert_rotated` |
| Integration | `integration.delivered`, `integration.failed` |
| Audit | `audit.chain_break` (P0; you should page yourself on this) |
| Compliance | `compliance.evaluated`, `compliance.framework_failed` |
| User / Auth | `user.invited`, `user.login`, `user.mfa_reset`, `user.erased` |

### Payload shape (common envelope)

```json
{
  "event_id": "uuid",
  "event_type": "finding.created",
  "occurred_at": "2026-05-18T10:30:00Z",
  "tenant_id": "uuid",
  "engagement_id": "uuid|null",
  "actor": {"id": "uuid|null", "email": "string|null"},
  "payload": {
    // event-specific; see below
  }
}
```

### Per-event payload schemas

The OpenAPI spec includes the canonical payload schemas under
`components/schemas/`. The most common:

| Event | Payload schema |
| --- | --- |
| `finding.created` | `{id, severity, title, cvss, scanner, scan_type, affected_endpoint, cve}` |
| `scan.completed` | `{id, profile, started_at, finished_at, findings_summary: {critical, high, medium, low, info}}` |
| `agent.disconnected` | `{agent_id, last_heartbeat, reason}` |
| `audit.chain_break` | `{first_bad_id, detected_at, rows_walked}` |
| `user.erased` | `{user_id, reason, rows_swept: {login_events, token_revocations}}` |

### Delivery guarantees

- At-least-once
- Exponential backoff (1s → 32s, 5 attempts default)
- Circuit breaker per integration (closes if downstream errors >50% over 1m)
- DLQ after final failure (`integration_dead_letters`)
- Auto-retry via cron task every 5 min (configurable)

Your endpoint MUST:
- Return 2xx within 10 seconds (timeout)
- Be idempotent on `event_id` (you may see duplicates)
- Verify the HMAC signature on every request

## Rate limits

```http
GET /api/v1/findings HTTP/1.1
...

HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 200
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1716035060

{"error":{"code":"rate_limited","message":"per-tenant cap exceeded","retry_after":60}}
```

Limits per plan: see `billing-plans-quotas.md`. Inspect your
caller's current usage via `GET /api/v1/usage`.

## Error responses

Consistent error envelope:
```json
{
  "error": {
    "code":    "<machine-readable>",
    "message": "<human-readable>",
    "request_id": "<UUID for support tickets>"
  }
}
```

Codes you'll see:

| Code | HTTP | Meaning |
| --- | --- | --- |
| `unauthorized` | 401 | Missing / invalid JWT |
| `forbidden` | 403 | Caller lacks the required permission |
| `mfa_required` | 412 | Caller has the permission but no recent MFA |
| `rate_limited` | 429 | Per-IP or per-tenant cap hit |
| `quota_exhausted` | 402 | Per-plan monthly quota hit |
| `data_residency_violation` | 451 | Tenant is pinned to a different region |
| `unpinned_scanner_image` | 503 | Production refuses unsigned scanner; operator must populate digests.json |
| `signature_mismatch` | 401 | Inbound webhook HMAC failed |
| `timestamp_skew` | 401 | Inbound webhook timestamp outside 5-min window |
| `internal` | 500 | Engineering error; quote the request_id in your support ticket |

## SCIM (provisioning users in bulk)

The platform exposes a SCIM 2.0 server at `/scim/v2/`. Customer
admins generate a SCIM token via the portal (today: operator-
provisioned; self-serve on roadmap).

Connector compatibility:
- Okta SCIM 2.0 ✓
- Azure AD / Entra ID ✓
- OneLogin ✓
- JumpCloud ✓
- Google Workspace (via SCIM 2.0 connector) ✓

SCIM filter support: `eq`, `sw`, `ew`, `co`, `pr`, AND/OR composites,
parenthesised groups, AND-binds-tighter precedence.

## SDK code samples

### Python: fetch findings

```python
import os, requests

api = "https://api.<env>"
jwt = os.environ["VAULTSCAN_JWT"]
tenant = os.environ["VAULTSCAN_TENANT_ID"]

resp = requests.get(
    f"{api}/api/v1/findings?severity=high,critical&status=open",
    headers={
        "Authorization": f"Bearer {jwt}",
        "X-Tenant-Id": tenant,
    },
    timeout=10,
)
resp.raise_for_status()
for f in resp.json():
    print(f["severity"], f["title"], f["affected_endpoint"])
```

### Go: post an inbound webhook event

```go
import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

secret := []byte(os.Getenv("VAULTSCAN_INBOUND_SECRET"))
body, _ := json.Marshal(map[string]any{
    "event":   "deploy.completed",
    "payload": map[string]string{"service": "checkout", "version": "1.4.2"},
})
ts := fmt.Sprintf("%d", time.Now().Unix())

mac := hmac.New(sha256.New, secret)
mac.Write([]byte(ts))
mac.Write([]byte("."))
mac.Write(body)
sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

req, _ := http.NewRequest("POST",
    "https://api.<env>/api/v1/integrations/"+intID+"/inbound",
    bytes.NewReader(body))
req.Header.Set("X-Vaultscan-Timestamp", ts)
req.Header.Set("X-Vaultscan-Signature", sig)
req.Header.Set("Content-Type", "application/json")

resp, _ := http.DefaultClient.Do(req)
// 200 = accepted; 401 = signature/timestamp; 5xx = retry with backoff
```

### TypeScript: subscribe to dashboard live updates

```typescript
const sse = new EventSource(
  `${apiUrl}/api/v1/dashboards/stream?topics=findings,scans`,
  { headers: { Authorization: `Bearer ${jwt}`, "X-Tenant-Id": tenant } }
);

sse.addEventListener("finding.created", (e) => {
  const data = JSON.parse(e.data);
  console.log("new finding:", data.severity, data.title);
});

sse.addEventListener("scan.completed", (e) => {
  // refresh the relevant chart
});
```

## Status page

`/api/v1/status` returns the platform's version + uptime +
per-component health. Use it to drive your own status page or alert
your team to platform-wide outages.

## Where to find each thing

| Topic | File |
| --- | --- |
| OpenAPI spec | `docs/api/openapi.yaml` |
| Event types | `backend/internal/eventbus/eventbus.go` `AllEventTypes()` |
| Inbound webhook reference | `docs/operations/inbound-webhooks.md` |
| Integration setup guides | `docs/operations/integration-setup-guides.md` |
| Rate limits per plan | `docs/operations/billing-plans-quotas.md` |
| Scanner tools list | `tools/scanner-images/<tool>/Dockerfile` |
| Architecture | `ARCHITECTURE.md` |

## Support

| Question | Where |
| --- | --- |
| API behaviour | Open a GitHub issue (`area/api` label) |
| OpenAPI spec gap | Open a GitHub issue (`area/openapi` label) |
| Production incident | Status page → engineering on-call |
| Sub-processor / DPA question | Customer's CSM |
| Custom integration build | Customer's CSM + sales engineering |
