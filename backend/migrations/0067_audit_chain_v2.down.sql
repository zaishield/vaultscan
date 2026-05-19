-- 0067_audit_chain_v2.down.sql
DROP INDEX IF EXISTS audit_logs_chain_hash_version_idx;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS chain_hash_version;
