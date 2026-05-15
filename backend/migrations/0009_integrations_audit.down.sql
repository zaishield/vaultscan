-- Reverses 0009_integrations_audit.up.sql.
DROP TABLE IF EXISTS bus_events             CASCADE;
DROP TABLE IF EXISTS audit_logs              CASCADE;
DROP TABLE IF EXISTS integration_deliveries  CASCADE;
DROP TABLE IF EXISTS integrations            CASCADE;
