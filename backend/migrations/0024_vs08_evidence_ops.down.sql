-- Reverses 0024_vs08_evidence_ops.up.sql.
DROP TABLE IF EXISTS evidence_chain_of_custody CASCADE;
ALTER TABLE finding_evidence DROP COLUMN IF EXISTS worm;
ALTER TABLE finding_evidence DROP COLUMN IF EXISTS encryption_key_version;
DROP TABLE IF EXISTS tenant_data_keys CASCADE;
