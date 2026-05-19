-- 0066_mfa_replay_rate_limit.up.sql
--
-- Two MFA hardening additions:
--
-- (a) Counter replay protection. RFC 6238 §5.2 mandates that within
--     a code's validity window, a presented code MUST NOT be accepted
--     twice. The previous Verify() implementation rejected nothing on
--     the second presentation — same code, second submission, same
--     30s window: both succeeded. We now persist last_used_counter
--     and refuse any code whose counter <= the stored one.
--
-- (b) Brute-force rate limit. With 1,000,000 6-digit codes and a ±1
--     window of drift tolerance (3/1M ≈ 3e-6 success per guess), an
--     attacker who can submit unlimited guesses converges fast. We
--     track failed verification attempts in a rolling 15-minute
--     window per user; on N=5 failures the account is locked for
--     15 minutes. Successful verify resets the counter.
--
-- Columns are NOT NULL with defaults so existing rows migrate cleanly.

ALTER TABLE user_mfa
    ADD COLUMN IF NOT EXISTS last_used_counter BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failed_verify_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failed_verify_window_start TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

COMMENT ON COLUMN user_mfa.last_used_counter IS
    'Highest TOTP counter ever accepted. Verify() rejects any code whose counter <= this value (RFC 6238 §5.2 replay defence).';

COMMENT ON COLUMN user_mfa.failed_verify_count IS
    'Failed Verify() attempts in the current 15-minute rolling window. Reset on successful verify, locked out at the platform-configured threshold.';

COMMENT ON COLUMN user_mfa.locked_until IS
    'When set in the future, Verify() refuses immediately regardless of code. Cleared on threshold reset.';
