# Customer admin guide

**Primary objective:** administer YOUR tenant — invite users,
configure scans, route findings into your tooling, demonstrate
compliance.

This is for the customer's tenant administrator (the person who
holds the `client_admin` role). For VaultScan-side admin, see
`platform-admin-day1.md`.

## What you can do (`client_admin` role permissions)

| Capability | Endpoint |
| --- | --- |
| Invite + manage users in your tenant | `POST /api/v1/users` + `/{user_id}` |
| Assign roles within your tenant | `POST /api/v1/users/{user_id}/roles` |
| Configure your IdP federation | `PUT /api/v1/tenants/{tenant_id}/branding` (SAML/OIDC settings) |
| Configure SCIM provisioning | (operator-provisioned today; self-serve on roadmap) |
| Manage engagements + scope | `POST /api/v1/engagements` + `/scope/*` |
| Upload authorization documents | `POST /api/v1/authorization-documents` |
| Configure scan profiles + schedules | `POST /api/v1/scans` + `/scan-profiles` |
| Configure integrations | `POST /api/v1/integrations` |
| Rotate integration HMAC secrets | `PUT /api/v1/integrations/{id}/signing-secret` |
| Read findings + acknowledge / risk-accept | `GET /api/v1/findings` + `PATCH` |
| Generate + schedule reports | `POST /api/v1/reports` + `/report-schedules` |
| White-label the portal (within your tenant) | `PUT /api/v1/tenants/{id}/branding` |
| Read your audit log | `GET /api/v1/audit` + `/export` |
| View tenant usage | `GET /api/v1/usage` |
| Set up MFA / manage devices | `POST /api/v1/auth/mfa/*` |
| Configure notification preferences | `POST /api/v1/notification-preferences` |

## What you CANNOT do (escalate to VaultScan support)

| Restricted | Why | Who |
| --- | --- | --- |
| Change your plan | Pricing decision | VaultScan sales / CSM |
| See another tenant's data | Multi-tenant isolation | Hard-blocked by RLS |
| Hard-delete your tenant | Data retention obligations | VaultScan support + contract review |
| Modify platform-wide policy | Platform-shared | VaultScan platform admin |
| Mint platform-admin JWTs | Platform-scoped | (only ZAISHIELD super-admins) |
| Bypass audit logging | By design | (impossible) |

## Common workflows

### Invite a new user

```bash
# Replace with your tenant + admin JWT.
TENANT=<your-tenant-id>
JWT=<your-admin-jwt>

curl -X POST "https://api.<env>/api/v1/users" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Tenant-Id: $TENANT" \
  -d '{
    "email":"new.user@yourorg.example",
    "full_name":"Jane Doe",
    "roles":["operator"],
    "partner_id":"<your-partner-id>",
    "tenant_id":"'$TENANT'"
  }'
```

Returns: a one-time enrollment link. Email it to the user. They
click → redirected to your IdP → sign in → MFA enrol → done.

If your org uses SCIM, the IdP creates the user automatically when
you assign them to the VaultScan app — no manual invite needed.

### Run your first scan

```bash
# 1. Create an engagement (one-shot or recurring scope)
ENG=$(curl -s -X POST "https://api.<env>/api/v1/engagements" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -d '{"code":"Q2-2026-VA","name":"Q2 VA","client_id":"<id>"}' | jq -r .id)

# 2. Add scope targets
curl -X POST "https://api.<env>/api/v1/engagements/$ENG/scope" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -d '[{"target_type":"domain","target_value":"yourorg.example","plane":"external"}]'

# 3. Upload signed authorization document (PDF)
curl -X POST "https://api.<env>/api/v1/authorization-documents" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -F "engagement_id=$ENG" -F "document_type=letter" \
  -F "file=@./authorization.pdf"

# 4. Submit a scan
curl -X POST "https://api.<env>/api/v1/scans" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -d '{"engagement_id":"'$ENG'","profile":"external_standard_va","intensity":"standard"}'
```

Watch progress via the portal dashboard OR
`GET /api/v1/scans` + filter by your engagement.

### Configure Slack notifications

See `integration-setup-guides.md` for the Slack walkthrough.

### Generate a quarterly executive report

```bash
# JSON:
curl -s "https://api.<env>/api/v1/reports?engagement=$ENG&type=executive&period=2026Q2" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" > q2-exec.json

# PDF:
curl -s "https://api.<env>/api/v1/reports/$REPORT_ID.pdf" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" -o q2-exec.pdf
```

You can also schedule reports: `POST /api/v1/report-schedules` with
a cron expression. The cron-runner picks them up + delivers via
your configured notification channel.

### Set up data residency (Business+ plans)

```bash
# Pin your tenant to one region (eu / us / apac):
curl -X PUT "https://api.<env>/api/v1/tenants/$TENANT/residency" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -d '{"region":"eu","reason":"GDPR — EU customer data"}'
```

After this, any write that lands on a non-EU pod returns
`451 Unavailable For Legal Reasons` with the pinned region in the
body. Your client SDK should retry against the pinned region's URL.

### Roll your IdP

When your IdP cert rotates (annual for most providers):

```bash
# Update the SAML metadata:
curl -X PUT "https://api.<env>/api/v1/tenants/$TENANT/branding" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -d '{"saml_metadata":"<new-metadata-xml>"}'

# Test from your IdP — sign in with a test account.
# Old certs continue to verify for a 24h grace.
```

### Erase a user (GDPR Article 17)

```bash
curl -X POST "https://api.<env>/api/v1/users/$USER_ID/erase" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" \
  -d '{"reason":"GDPR Art 17 — subject request"}'
```

Returns the row-count report (login_events_swept, etc.). User can
no longer log in; their identifier in audit logs becomes
`erased+<short-hash>@invalid.local`.

## Daily / weekly

- **Daily**: scan the new-findings queue, triage Critical / High
  within 24h
- **Weekly**: review the integration delivery DLQ
  (`GET /api/v1/integrations/$ID/dead-letters`)
- **Monthly**: review user list — disable accounts no longer needed
- **Quarterly**: rotate integration HMAC secrets
- **Annually**: rotate IdP certs + review your compliance pack

## Reading your usage

```bash
curl -s "https://api.<env>/api/v1/usage" \
  -H "Authorization: Bearer $JWT" -H "X-Tenant-Id: $TENANT" | jq
```

Returns your plan + current usage + remaining quota for: monthly
scans, concurrent scans, active users, evidence retention.

At >80% utilisation, a `quota.warning` event fires (configurable via
notification preferences) and your CSM is notified.

## Honest limitations

- **No self-serve plan upgrade** — your CSM owns this. Email them.
- **No customer-facing impersonation** — VaultScan support cannot
  log in as you to debug; they ask you to screen-share.
- **No customer-facing password reset** — IdP-only; if your IdP is
  down, sign-in is down. Use your IdP's recovery flow.
- **No native real-time chat / collaboration** — findings have
  comments; that's it. Real conversations happen in your Slack /
  email / Jira.

## Getting help

| Issue | Where |
| --- | --- |
| Can't sign in | Your IdP first; then VaultScan support |
| Integration not firing | Check `GET /api/v1/integrations/$ID/dead-letters` |
| Scan stuck queued | Check your usage; you may be at quota |
| Wrong finding result | File a finding feedback in-portal; VaultScan triages |
| Need a custom report format | Discuss with CSM — possible via custom template |
| Cost / billing question | Your AE / CSM |
| Suspected platform issue | Status page first: `/api/v1/status`; then support |

## Related

- `customer-onboarding.md` — your Day-0 → Week-1 setup
- `integration-setup-guides.md` — per-vendor integration setup
- `agent-fleet-onboarding.md` — installing on-prem scanner agents
- `inbound-webhooks.md` — pushing events INTO VaultScan
- `gdpr-erasure.md` — Article 17 procedure
- `data-residency.md` — pin model + multi-region routing
