-- 0048_manage_signers_permission.down.sql
DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE code = 'manage_signers'
);
DELETE FROM permissions WHERE code = 'manage_signers';
