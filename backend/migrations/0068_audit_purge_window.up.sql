-- 0068_audit_purge_window.up.sql
--
-- Allow the audit archiver to actually DELETE source rows.
--
-- Migration 0029 installed a BEFORE UPDATE OR DELETE trigger on
-- audit_logs that raises EXCEPTION on every delete attempt — the
-- correct default (audit rows are append-only at the DB layer), but
-- it also blocked the archiver's purgeOldArchives path: the cron
-- swept up rows already exported to long-term storage, but every
-- DELETE tripped the trigger and the cron silently fell over.
--
-- We extend the trigger to allow DELETE when the session-local GUC
-- `vaultscan.audit_purge_authorised` is set to 'on'. The archiver
-- sets this GUC at the start of its purge transaction; nothing else
-- in the codebase does. An attacker who acquires DB write would have
-- to also discover and set the GUC — a low bar, but the strong
-- protection is the application-level discipline that only the
-- archiver opens this window.

CREATE OR REPLACE FUNCTION vaultscan_audit_logs_immutable() RETURNS trigger AS $$
BEGIN
  -- UPDATEs are always forbidden — no exception path.
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'audit_logs are append-only: UPDATE rejected';
  END IF;
  -- DELETE allowed only when the session has set the purge GUC.
  IF TG_OP = 'DELETE' THEN
    IF current_setting('vaultscan.audit_purge_authorised', true) = 'on' THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_logs are append-only: DELETE rejected (set vaultscan.audit_purge_authorised=on within archiver tx)';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
