-- Reverses 0023_vs07_findings_ops.up.sql.
ALTER TABLE findings DROP COLUMN IF EXISTS suppression_rule_id;
DROP TABLE IF EXISTS finding_suppression_rules CASCADE;
DROP TABLE IF EXISTS finding_severity_overrides CASCADE;
ALTER TABLE findings DROP COLUMN IF EXISTS severity_overridden_from;
DROP INDEX IF EXISTS findings_cluster_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS cluster_id;
DROP TABLE IF EXISTS finding_clusters CASCADE;
