-- HS-01 deepening: real mTLS at the agent gateway.
--
-- The gateway accepts TLS connections only from agents whose client
-- certificate (a) is signed by an active issuer in agent_ca_certificates,
-- and (b) has a fingerprint matching an un-revoked row in
-- agent_certificates. The first check is enforced by Go's standard
-- library at handshake time via tls.Config.ClientAuth; the second runs
-- in a VerifyPeerCertificate callback so a stolen-but-not-yet-revoked
-- cert can be cut off mid-session.

CREATE TABLE agent_ca_certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,             -- e.g. "vaultscan-agent-ca-2026"
    cert_pem        TEXT NOT NULL,
    fingerprint     TEXT NOT NULL UNIQUE,             -- sha256 of DER
    not_before      TIMESTAMPTZ NOT NULL,
    not_after       TIMESTAMPTZ NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_ca_certificates_active_idx
    ON agent_ca_certificates(enabled, not_after) WHERE enabled = true;

-- Trust audit: every accepted handshake + every rejection at the verify
-- callback gets a row so operators can see in real time which agents
-- are connecting and which have been rejected and why.
CREATE TABLE agent_mtls_handshakes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    fingerprint     TEXT NOT NULL,
    decision        TEXT NOT NULL,            -- accepted | rejected_unknown | rejected_revoked | rejected_expired
    reason          TEXT,
    remote_addr     INET,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_mtls_handshakes_recent_idx
    ON agent_mtls_handshakes(occurred_at DESC);
CREATE INDEX agent_mtls_handshakes_agent_idx
    ON agent_mtls_handshakes(agent_id, occurred_at DESC) WHERE agent_id IS NOT NULL;
