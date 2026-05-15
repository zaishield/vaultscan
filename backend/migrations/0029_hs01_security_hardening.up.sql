-- HS-01 deepening: per-IP brute-force shield, password-leak gate.
--
-- The user-level lockout (0017) catches an attacker that hammers a single
-- account. An attacker iterating across accounts from a single IP slips
-- past that. The auth_ip_lockouts table tracks per-IP failure counts and
-- auto-locks an IP for 15 minutes after 25 failures in any 15-minute
-- window (regardless of which user account is targeted).

CREATE TABLE auth_ip_failures (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip          INET NOT NULL,
    email       TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_ip_failures_recent_idx
    ON auth_ip_failures(ip, occurred_at DESC);

CREATE TABLE auth_ip_lockouts (
    ip          INET PRIMARY KEY,
    locked_until TIMESTAMPTZ NOT NULL,
    reason      TEXT NOT NULL,
    locked_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_ip_lockouts_expires_idx ON auth_ip_lockouts(locked_until);

-- Compromised-password sentinel. The IT admin loads SHA-1 hash prefixes
-- (first 5 chars = bucket; suffix = 35-char tail) periodically from an
-- offline HIBP-style dump; the password-change endpoint refuses any
-- new password whose hash prefix+suffix matches a row.
CREATE TABLE compromised_password_buckets (
    bucket_prefix CHAR(5) NOT NULL,
    suffix        CHAR(35) NOT NULL,
    seen_count    INTEGER NOT NULL DEFAULT 1,
    loaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_prefix, suffix)
);
CREATE INDEX compromised_password_bucket_idx
    ON compromised_password_buckets(bucket_prefix);

-- Defence in depth on top of the existing REVOKE on audit_logs: a trigger
-- that explicitly raises on UPDATE / DELETE. This protects against
-- accidental SUPERUSER role escalation in a maintenance shell.
CREATE OR REPLACE FUNCTION vaultscan_audit_logs_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs are append-only: % rejected', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION vaultscan_audit_logs_immutable();
