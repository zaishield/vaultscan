-- Reverses 0026_vs10_reporting_ops.up.sql.
ALTER TABLE reports DROP COLUMN IF EXISTS pdf_renderer;
DROP TABLE IF EXISTS report_schedules         CASCADE;
DROP TABLE IF EXISTS report_template_compliance CASCADE;
DROP TABLE IF EXISTS compliance_controls      CASCADE;
