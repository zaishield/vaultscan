-- 0049_cloud_posture_coverage.down.sql
ALTER TABLE cloud_posture_snapshots
    DROP COLUMN IF EXISTS automated_count,
    DROP COLUMN IF EXISTS manual_count,
    DROP COLUMN IF EXISTS not_applicable_count,
    DROP COLUMN IF EXISTS total_count,
    DROP COLUMN IF EXISTS coverage_percent;
