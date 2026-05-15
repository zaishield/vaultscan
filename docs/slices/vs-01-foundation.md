# VS-01 · Platform Foundation & Authentication

| Acceptance Criterion (Plan §VS-01)                                                | Implementation                                                                          |
|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| Every API request carries `tenant_id`; no query returns cross-tenant data         | `backend/internal/middleware/middleware.go` (`TenantScope`); every service WHERE clauses include `tenant_id` |
| All 14 RBAC roles log in and see only permitted nav items                         | Migration `0001_platform_foundation.up.sql` seeds 14 roles + permission matrix in `0010_seed_platform.up.sql`; `RequirePermission` middleware enforces |
| MFA enforced for Super Admin, Partner Admin, Tenant Admin, Pentester              | `backend/internal/middleware/middleware.go` (`RequireMFA`) attached to evidence + aggressive scan routes; dev token sets `mfa` claim |
| SAML 2.0 and OIDC SSO tested with mock IdP                                        | `backend/internal/auth/jwt.go` `Verifier.Parse` validates JWTs; production uses Keycloak (`infra/compose/docker-compose.yml`) |
| Partner hierarchy (ZAISHIELD → Distributor → Reseller → Tenant) traversal correct | `backend/internal/partners/service.go` (`HierarchyForTenant`); reseller-distributor mapping in `partner_reseller_mapping` |
| All migrations versioned and rollback validated                                   | `backend/internal/db/migrate.go` records sha256 hash + version; checksum drift fails the boot |

## Tables created (Blueprint §20.1, §20.2)

`platforms`, `partner_types`, `partners`, `partner_reseller_mapping`, `tenants`,
`partner_customer_mapping`, `tenant_settings`, `tenant_branding`, `users`,
`roles`, `permissions`, `role_permissions`, `user_roles`.

## Key files

- `backend/migrations/0001_platform_foundation.up.sql`
- `backend/migrations/0010_seed_platform.up.sql`
- `backend/internal/auth/{identity.go,jwt.go}`
- `backend/internal/middleware/middleware.go`
- `backend/internal/tenants/service.go`
- `backend/internal/partners/service.go`
- `frontend/src/store/auth.ts`
- `frontend/src/pages/Login.tsx`
