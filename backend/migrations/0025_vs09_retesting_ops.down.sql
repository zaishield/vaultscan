-- Reverses 0025_vs09_retesting_ops.up.sql.
DROP TABLE IF EXISTS retest_diffs        CASCADE;
DROP TABLE IF EXISTS retest_batch_items   CASCADE;
DROP TABLE IF EXISTS retest_batches       CASCADE;
ALTER TABLE findings DROP COLUMN IF EXISTS last_retest_at;
ALTER TABLE findings DROP COLUMN IF EXISTS last_retest_outcome;
ALTER TABLE tenant_settings DROP COLUMN IF EXISTS auto_retest_on_remediated;
