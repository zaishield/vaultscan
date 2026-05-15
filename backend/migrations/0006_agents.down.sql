-- Reverses 0006_agents.up.sql.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_agent_fk;
DROP TABLE IF EXISTS agent_audit_logs        CASCADE;
DROP TABLE IF EXISTS agent_update_history     CASCADE;
DROP TABLE IF EXISTS agent_job_queue          CASCADE;
DROP TABLE IF EXISTS agent_assigned_scope     CASCADE;
DROP TABLE IF EXISTS agent_tool_inventory     CASCADE;
DROP TABLE IF EXISTS agent_policies           CASCADE;
DROP TABLE IF EXISTS agent_heartbeats         CASCADE;
DROP TABLE IF EXISTS agent_certificates       CASCADE;
DROP TABLE IF EXISTS agent_enrollment_tokens  CASCADE;
DROP TABLE IF EXISTS agents                   CASCADE;
