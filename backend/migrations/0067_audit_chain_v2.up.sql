-- 0067_audit_chain_v2.up.sql
--
-- Audit chain hash v2: include occurred_at in the hash material.
--
-- Why this matters: the v1 chain bound (event, actor, ip, ua,
-- platform/partner/tenant, target_*, payload) but NOT occurred_at.
-- An attacker (or a buggy app path) could re-issue an audit row at
-- a different occurred_at while preserving the rest of the tuple
-- and the hash would still validate — meaning the row could appear
-- to have happened at a different time without tripping verification.
--
-- We CANNOT simply switch the algorithm: existing chains were
-- computed under v1 and would all fail v2 verification. Instead:
--
--   1. Add a chain_hash_version column (default 1 = v1 algorithm).
--   2. New writes set chain_hash_version=2 and include occurred_at
--      in the hash material.
--   3. VerifyDeep + VerifyIncremental dispatch on the column when
--      recomputing the expected hash.
--
-- This preserves every historical row's verifiability under its
-- original algorithm while strengthening every row written from
-- this commit forward.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS chain_hash_version SMALLINT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS audit_logs_chain_hash_version_idx
    ON audit_logs(chain_hash_version)
    WHERE chain_hash_version <> 1;

COMMENT ON COLUMN audit_logs.chain_hash_version IS
    'Which hash algorithm produced chain_hash: 1=v1 (no occurred_at), 2=v2 (includes occurred_at). VerifyDeep/Incremental dispatch on this.';
