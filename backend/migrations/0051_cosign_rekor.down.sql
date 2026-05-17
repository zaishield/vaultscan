-- 0051_cosign_rekor.down.sql
DROP INDEX IF EXISTS cosign_verifications_rekor_idx;
ALTER TABLE cosign_verifications
    DROP COLUMN IF EXISTS rekor_log_id,
    DROP COLUMN IF EXISTS rekor_log_index,
    DROP COLUMN IF EXISTS rekor_integrated_at;
