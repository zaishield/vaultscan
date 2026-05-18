DROP INDEX IF EXISTS integration_dead_letters_sweeper_idx;
ALTER TABLE integration_dead_letters
  DROP COLUMN IF EXISTS last_retry_at,
  DROP COLUMN IF EXISTS retry_count,
  DROP COLUMN IF EXISTS give_up_at;
