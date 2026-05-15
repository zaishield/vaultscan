-- Reverses 0008_retesting_reporting.up.sql.
DROP TABLE IF EXISTS report_exports          CASCADE;
DROP TABLE IF EXISTS report_approvals         CASCADE;
DROP TABLE IF EXISTS reports                  CASCADE;
DROP TABLE IF EXISTS report_templates         CASCADE;
DROP TABLE IF EXISTS retest_evidence          CASCADE;
DROP TABLE IF EXISTS retest_results           CASCADE;
DROP TABLE IF EXISTS retest_assignments       CASCADE;
DROP TABLE IF EXISTS retest_requests          CASCADE;
