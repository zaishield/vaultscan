-- Reverses 0029_hs01_security_hardening.up.sql.
DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
DROP FUNCTION IF EXISTS vaultscan_audit_logs_immutable();
DROP TABLE IF EXISTS compromised_password_buckets CASCADE;
DROP TABLE IF EXISTS auth_ip_lockouts CASCADE;
DROP TABLE IF EXISTS auth_ip_failures CASCADE;
