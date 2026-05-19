-- 0066_mfa_replay_rate_limit.down.sql
ALTER TABLE user_mfa
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS failed_verify_window_start,
    DROP COLUMN IF EXISTS failed_verify_count,
    DROP COLUMN IF EXISTS last_used_counter;
