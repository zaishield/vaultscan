-- Reverses 0012_audit_log_independence.up.sql.
-- The up: dropped FKs on audit_logs/scope_decision_logs/scan_approval_logs;
-- coerced audit_logs.payload from JSONB to TEXT.
-- Down: we can't perfectly restore the FK + JSONB shape without knowing the
-- target tables, so this is a best-effort: convert payload back to JSONB
-- (the application keeps emitting JSON strings, so the cast works), but we
-- intentionally leave the FK references off because re-adding them would
-- block legitimate cross-tenant inserts that 0012 was added to support.

ALTER TABLE audit_logs ALTER COLUMN payload TYPE JSONB USING payload::jsonb;
