# GDPR Article 17 Erasure Runbook

Runbook for handling a customer's "right to be forgotten" request.

## Scope

`POST /api/v1/users/{user_id}/erase` pseudonymises a single user's PII
across these tables in one transaction:

| Table              | Action                                       |
| ------------------ | -------------------------------------------- |
| users              | email/full_name redacted; status = 'erased'  |
| login_events       | email column nulled (ip retained for sec-ops) |
| token_revocations  | reason text cleared                           |

The `audit_logs` table is **intentionally untouched** — its rows are
hash-chained (VerifyDeep would break on any in-place edit). The audit
chain is retained under the separate "accountability obligation"
legal basis, which every supervisory authority I've checked accepts
when the rows contain user_id only and not free-text PII.

## Preconditions

- Operator account with `create_tenant` permission
- MFA verified on the operator session (`POST /api/v1/auth/mfa/verify`)
- Operator MUST NOT be the user being erased (self-erasure is blocked
  at handler level — preserves the actor invariant in the resulting
  audit row)

## Procedure

```bash
# 1. Locate the user via /api/v1/auth/me as them, or admin search
USER_ID="00000000-0000-0000-0000-000000000123"

# 2. Issue the erase request
curl -X POST "https://api.vaultscan.zaishield.com/api/v1/users/${USER_ID}/erase" \
  -H "Authorization: Bearer ${OPERATOR_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"reason": "GDPR Art 17 ticket #4521 — user-confirmed via verified channel 2026-05-12"}'

# 3. Verify the response carries the row counts
# {
#   "status": "erased",
#   "report": {
#     "user_id": "...",
#     "login_events_swept": 14,
#     "token_revocations_swept": 1,
#     "audit_rows_retained": true
#   }
# }
```

## Verification

After erasure, confirm:

```sql
-- users row pseudonymised
SELECT email, full_name, status FROM users WHERE id = '<user_id>';
-- expect: erased+<uuid>@invalid.local | ERASED USER <short_id> | erased

-- login_events emails nulled for this user
SELECT COUNT(*) FROM login_events WHERE user_id = '<user_id>' AND email IS NOT NULL;
-- expect: 0

-- token_revocations.reason cleared
SELECT reason FROM token_revocations WHERE user_id = '<user_id>';
-- expect: NULL

-- audit chain has one 'user.erased' row
SELECT id, event, payload FROM audit_logs
 WHERE target_id = '<user_id>' AND event = 'user.erased'
 ORDER BY id DESC LIMIT 1;
```

## Customer-facing response template

> We confirm completion of your erasure request under Article 17.
>
> The following personal data has been pseudonymised in our systems:
> - Account profile (email, name)
> - Login history (IP retained under legitimate-interest basis for
>   security incident investigation, expires after 90 days)
> - Active sessions revoked
>
> Audit log entries referencing your user ID are retained under our
> regulatory accountability obligations. These entries contain only
> the opaque user identifier and no personally identifying free-text.
>
> Reference: <reason string from request>
> Erasure timestamp (UTC): <occurred_at from audit row>

## Edge cases

- **Self-erasure attempt** — returns 400 with "erase cannot be
  self-served via this endpoint". Direct the user to support; an
  operator must run the request on their behalf so the audit row
  has a non-erased actor.

- **User has elevated permissions** — the erase succeeds, but
  consider whether their assigned roles should be revoked too via
  `POST /api/v1/users/{id}/revoke-tokens` and/or removing their
  role grants before erasure.

- **User is a partner-admin** — verify with the partner contract
  that erasure of a partner staff account does not breach the
  partner's record-keeping obligations.

## What this runbook does NOT cover

- Tenant-scope erasure (the customer org leaving entirely). That's
  the `tenant-offboarding.md` runbook.
- Engagement-scope evidence purge. That's the WORM exception in
  `evidence-retention.md`.
