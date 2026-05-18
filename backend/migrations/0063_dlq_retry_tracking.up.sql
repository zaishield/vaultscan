-- 0063_dlq_retry_tracking.up.sql
--
-- Add the columns the automated DLQ retry sweeper needs:
--   * last_retry_at — when the sweeper last attempted this row.
--     The sweeper applies exponential backoff keyed off this
--     column: don't retry a row whose last_retry_at is younger
--     than 2^retry_count minutes.
--   * retry_count — how many times the sweeper has retried this
--     row. Distinct from `attempts` (which counts the ORIGINAL
--     delivery attempts before the row was enqueued in the DLQ).
--   * give_up_at — once retry_count exceeds the per-integration
--     budget, the sweeper sets this. give_up_at IS NOT NULL → row
--     stays in DLQ for human inspection but the sweeper ignores it.

ALTER TABLE integration_dead_letters
  ADD COLUMN IF NOT EXISTS last_retry_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS retry_count   INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS give_up_at    TIMESTAMPTZ;

-- Partial index for the sweeper's hot query: "find pending DLQ rows
-- that are due for retry." Without this, the sweeper does a full
-- scan of integration_dead_letters every tick.
CREATE INDEX IF NOT EXISTS integration_dead_letters_sweeper_idx
  ON integration_dead_letters (last_retry_at NULLS FIRST)
  WHERE resolved_at IS NULL AND give_up_at IS NULL;
