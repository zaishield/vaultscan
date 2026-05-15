-- Reverses 0005_scans_scanners.up.sql.
DROP TABLE IF EXISTS scope_decision_logs   CASCADE;
DROP TABLE IF EXISTS scan_approval_logs     CASCADE;
DROP TABLE IF EXISTS scan_tasks             CASCADE;
DROP TABLE IF EXISTS scan_jobs              CASCADE;
DROP TABLE IF EXISTS scan_profiles          CASCADE;
DROP TABLE IF EXISTS scanner_node_registry  CASCADE;
