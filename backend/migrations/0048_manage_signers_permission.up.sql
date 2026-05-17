-- 0048_manage_signers_permission.up.sql
-- Adds the manage_signers permission gating the cosign-trust-policy
-- handlers (list / register / revoke trusted keys, dry-run verify).
-- Granted to platform admins by default; partner / tenant roles
-- must explicitly opt in.

INSERT INTO permissions(code, description) VALUES
    ('manage_signers', 'Register, list, revoke cosign trusted keys')
ON CONFLICT (code) DO NOTHING;

-- Grant to any role that already holds create_tenant (platform-admin proxy).
INSERT INTO role_permissions(role_id, permission_id)
SELECT rp.role_id, p2.id
  FROM role_permissions rp
  JOIN permissions p1 ON p1.id = rp.permission_id AND p1.code = 'create_tenant'
  JOIN permissions p2 ON p2.code = 'manage_signers'
ON CONFLICT DO NOTHING;
