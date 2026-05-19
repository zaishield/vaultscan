-- 0065_sso_config_provisioning.up.sql
--
-- Tenant-curated SSO provisioning + role-allowlist columns on
-- tenant_sso_config. Closes two P0 federation gaps:
--
--   1. Auto-provisioning was unconditional — any IdP could trigger
--      a fresh user row by asserting an unknown email. We now require
--      the tenant operator to opt in via allow_auto_provision, and
--      the federation layer additionally requires email_verified=true
--      from the IdP for OIDC tenants.
--
--   2. IdP-asserted role codes were granted verbatim — any group
--      string matching a platform role code (zaishield_super_admin
--      etc) was honoured. Tenants now publish an allowlist; legacy
--      tenants with NULL fall back to a hard-coded deny on platform-
--      and partner-tier roles.
--
-- Both columns are NULLable + default-safe so the migration is a
-- no-op for existing tenants until the operator updates the config.

ALTER TABLE tenant_sso_config
    ADD COLUMN IF NOT EXISTS allow_auto_provision BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS allowed_role_codes   TEXT[]  NOT NULL DEFAULT '{}'::text[];

COMMENT ON COLUMN tenant_sso_config.allow_auto_provision IS
    'When true, first-time SSO sign-in may create the user row. Default false — SCIM is the canonical provisioner. SAML tenants enabling this trust their IdP without email_verified.';

COMMENT ON COLUMN tenant_sso_config.allowed_role_codes IS
    'Tenant-curated allowlist of role codes (matched against IdP `roles`/`groups`). Empty = legacy default-deny on platform/partner-tier roles; only tenant-scoped viewer/operator roles flow through.';
