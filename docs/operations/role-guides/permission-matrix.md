# Permission matrix (public reference)

Canonical list of every permission the platform's RBAC layer
enforces. Generated from `grep -oP 'RequirePermission\("\K[a-z_]+(?=\")'
backend/internal/api/server.go` and verified against the role
definitions in `backend/migrations/0010_seed_platform.up.sql`.

When a role doesn't have the listed permission, the endpoint returns
`403 Forbidden`. The 11-case `backend/test/integration/permission_
matrix_test.go` asserts this for the GA endpoints.

## The permissions

| Permission | What it gates | Default holders |
| --- | --- | --- |
| `approve_aggressive_scan` | Approve a scan with `intensity=deep` | mssp_manager, pentester |
| `approve_scope` | Approve scope target additions | mssp_manager |
| `create_engagement` | Create / modify engagements | mssp_manager, distributor_admin |
| `create_partner` | Create new partner orgs (under ZAISHIELD) | zaishield_super_admin |
| `create_scan_job` | Submit a scan | pentester, client_admin |
| `create_tenant` | Create / modify tenants (incl. plan changes, isolation, residency) | distributor_admin, zaishield_super_admin |
| `download_evidence` | Pull raw evidence blobs (decrypted) | mssp_manager, pentester |
| `edit_findings` | Triage, assign, mark-fixed, risk-accept | pentester, client_admin |
| `execute_retest` | Run a retest scan | pentester |
| `generate_report` | Render executive / technical reports | mssp_manager, pentester |
| `manage_agents` | Provision / enroll / revoke on-prem agents | mssp_manager, client_admin |
| `manage_branding` | White-label partner / tenant appearance | distributor_admin, client_admin |
| `manage_integrations` | Configure / rotate Jira / Slack / SIEM / webhook integrations | mssp_manager, client_admin |
| `manage_signers` | Manage report signing keys + co-signers | mssp_manager |
| `request_retest` | Open a retest request (does NOT execute) | client_admin, client_viewer |
| `trigger_emergency_stop` | Issue emergency-stop for any running scan / agent | client_admin, mssp_manager |
| `upload_authorization` | Upload authorization documents (engagement gating) | mssp_manager, client_admin |
| `view_audit_log` | Read this tenant's audit log | client_admin, auditor |
| `view_audit_logs` | (Same as above; legacy plural variant) | (same) |
| `view_findings` | Read findings + their evidence metadata | client_admin, client_viewer, auditor, pentester |

## MFA-gated endpoints

These require BOTH the permission above AND a recent MFA challenge.
Failing the MFA gate returns `412 Precondition Required` even if the
permission is held.

| Endpoint | Permission + MFA |
| --- | --- |
| `POST /api/v1/tenants` | `create_tenant` + MFA |
| `POST /api/v1/tenants/{id}/suspend` | `create_tenant` + MFA |
| `POST /api/v1/tenants/{id}/promote-isolation` | `create_tenant` + MFA |
| `POST /api/v1/auth/jwt-keys/rotate` | `create_tenant` + MFA |
| `GET /api/v1/evidence` (download) | `download_evidence` + MFA |
| `POST /api/v1/platform/break-glass/redeem` | (any) + MFA |
| `POST /api/v1/auth/mfa` operations | (caller's own) + MFA |

## Built-in roles

Defined in `backend/migrations/0010_seed_platform.up.sql`. Each role
is a curated bundle of permissions; customers can compose custom
roles with the `create_role` permission (platform admin only).

| Role | Audience | Typical permissions |
| --- | --- | --- |
| `zaishield_super_admin` | ZAISHIELD platform admin | all |
| `distributor_admin` | Distributor partner admin | create_partner, manage_branding, create_engagement |
| `mssp_manager` | MSSP / reseller admin | create_engagement, approve_scope, generate_report, manage_signers |
| `pentester` | MSSP-side delivery engineer | create_scan_job, edit_findings, execute_retest, download_evidence |
| `client_admin` | Customer's tenant administrator | manage_integrations, manage_branding, view_audit_log, manage_agents, create_scan_job, edit_findings, request_retest, trigger_emergency_stop |
| `client_viewer` | Customer's read-only user | view_findings, request_retest |
| `auditor` | External auditor (read-only) | view_findings, view_audit_log |
| `system` | Platform-internal | (not minted as a JWT; used for audit attribution of background tasks) |

## Custom roles

```bash
# Create:
curl -X POST "$API/api/v1/roles" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "code":"security_analyst",
    "name":"Security Analyst",
    "permissions":["view_findings","edit_findings","request_retest"]
  }'

# Assign to a user (scoped to a tenant):
curl -X POST "$API/api/v1/users/$USER_ID/roles" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"role":"security_analyst","scope_tenant":"<id>"}'
```

## How permissions are checked

```
Request → middleware.Auth (JWT verify)
       → middleware.TenantScope (resolves X-Tenant-Id)
       → middleware.TenantBinding (sets Postgres GUC)
       → middleware.RequirePermission("<perm>") ← here
       → middleware.RequireMFA() (for MFA-gated endpoints) ← here
       → handler
```

`RequirePermission` walks the caller's JWT claims `.roles[]`, fetches
each role's permission set, and checks for membership. Permission
checks are O(1) — sets are precomputed at startup.

The JWT claims also carry a `mfa_at` timestamp. `RequireMFA` checks
that timestamp is within the past N minutes (default 15).

## How to add a new permission

```text
1. Add the permission name to the canonical list in backend/internal/
   auth/identity.go's permissions registry.
2. Add it to the role definitions in 00XX_role_perms_extension.up.sql.
3. Add the RequirePermission middleware to the relevant route in
   backend/internal/api/server.go.
4. Add a case to backend/test/integration/permission_matrix_test.go.
5. Update this matrix doc.
```

## How to revoke a permission across the platform

Permissions are not revocable per-user — they come from roles. To
remove a permission:

1. Either modify the role to remove it (affects everyone with the
   role)
2. Or re-grant a narrower role to the user

A user can have multiple roles; their effective permission set is
the union.

## Audit trail

EVERY permission grant / revocation lands an audit row:
- `role.granted` — `{user, role, scope_tenant, scope_partner, by}`
- `role.revoked` — `{user, role, by, reason}`
- `permission.denied` — `{user, endpoint, required, held}` (only
  when DENY happens; not on success — too noisy)

Query for the role-grant history of a single user:
```sql
SELECT occurred_at, event, payload
  FROM audit_logs
 WHERE target_id = '<user-id>'
   AND event IN ('role.granted', 'role.revoked')
 ORDER BY occurred_at DESC;
```

## Related

- `customer-admin.md` — what `client_admin` can do
- `auditor.md` — what `auditor` can do
- `support-engineer.md` — what VaultScan support can do
- `security-incident-commander.md` — break-glass elevations
