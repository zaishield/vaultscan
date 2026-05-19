-- 0065_sso_config_provisioning.down.sql
ALTER TABLE tenant_sso_config
    DROP COLUMN IF EXISTS allowed_role_codes,
    DROP COLUMN IF EXISTS allow_auto_provision;
