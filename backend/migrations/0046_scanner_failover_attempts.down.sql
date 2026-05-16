BEGIN;
DROP INDEX IF EXISTS scanner_failover_attempts_pair_idx;
DROP INDEX IF EXISTS scanner_failover_attempts_recent_idx;
DROP TABLE IF EXISTS scanner_failover_attempts;
COMMIT;
