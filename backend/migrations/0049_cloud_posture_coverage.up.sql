-- 0049_cloud_posture_coverage.up.sql
--
-- Adds the automation-coverage breakdown alongside the headline
-- score on cloud_posture_snapshots. Coverage = automated / (automated
-- + manual) × 100 — i.e. what fraction of controls we actually
-- checked vs. deferred to manual console review. Without this,
-- customers see "100% compliant" on a snapshot whose automation
-- coverage is 30%, which mis-represents posture.

ALTER TABLE cloud_posture_snapshots
    ADD COLUMN IF NOT EXISTS automated_count    INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS manual_count       INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS not_applicable_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_count        INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS coverage_percent   NUMERIC(5,2);

COMMENT ON COLUMN cloud_posture_snapshots.coverage_percent
    IS 'automated / (automated + manual) * 100 — fraction of controls actually checked';
