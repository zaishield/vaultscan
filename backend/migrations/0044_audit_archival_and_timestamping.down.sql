BEGIN;
DROP INDEX IF EXISTS audit_tsa_anchors_anchored_at_idx;
DROP TABLE IF EXISTS audit_tsa_anchors;
DROP INDEX IF EXISTS audit_archive_runs_unpurged_idx;
DROP INDEX IF EXISTS audit_archive_runs_range_idx;
DROP TABLE IF EXISTS audit_archive_runs;
COMMIT;
