-- Reverses 0007_findings_evidence.up.sql.
DROP TABLE IF EXISTS evidence_access_logs    CASCADE;
DROP TABLE IF EXISTS finding_evidence         CASCADE;
DROP TABLE IF EXISTS finding_comments         CASCADE;
DROP TABLE IF EXISTS finding_status_history   CASCADE;
DROP TABLE IF EXISTS finding_assignments      CASCADE;
DROP TABLE IF EXISTS findings                 CASCADE;
