-- 0068_audit_purge_window.down.sql
-- Restore the strict 0029 trigger: every UPDATE and DELETE rejected.
CREATE OR REPLACE FUNCTION vaultscan_audit_logs_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs are append-only: % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;
