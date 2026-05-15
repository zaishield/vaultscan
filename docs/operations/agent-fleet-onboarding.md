# Agent Fleet Onboarding

Owns: customer-success + delivery engineering.

Used when a tenant wants to install VAULTSCAN internal agents. The
flow is one-time per tenant (the CA + per-agent enrolment artifacts
are tenant-scoped) and the agents continue self-rotating via the
HS-01 mTLS / VS-06 CSR pipeline thereafter.

## Pre-conditions

- [ ] Tenant has an engagement in status `active` with a signed
      authorization document on file
      (`SELECT count(*) FROM authorization_documents WHERE engagement_id=<eng>`
      ≥ 1).
- [ ] Customer's network team has approved outbound HTTPS:443 to
      `agent-gateway.<region>.vaultscan.zaishield.com` from the
      subnets the agents will sit in.
- [ ] Agent installer package signed by the cloud signer is
      available at `https://updates.zaishield.com/agent/<version>`
      AND its manifest is published via
      `POST /api/v1/agent-updates`. Verify with
      `agents.VerifyBundleSig` smoke test before sharing.
- [ ] You hold a JWT with `manage_agents` permission and MFA
      verified (HS-01).

## Step 1 — Provision agent records

For each agent the customer plans to install, mint a placeholder row
+ one-time enrolment token:

```bash
for name in dc01 dc02 cloud-edge-01; do
  curl -fsS -X POST https://api/api/v1/agents \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Tenant-Id: $TENANT" \
    -d "{\"name\":\"$name\",\"form_factor\":\"linux_vm\"}"
done
```

Each response carries `enroll_token` (one-time, 24h TTL). Store
in 1Password under `vaultscan/<tenant>/agents/<name>`.

**Verification**: `SELECT name, status FROM agents WHERE tenant_id=<t>`
shows every requested agent in `status='pending'`.

## Step 2 — Plant the CA trust on the host

The agent verifies the gateway server cert against
`<data-dir>/gateway-ca.pem`. Ship it via configuration management
(salt / ansible / k8s ConfigMap) BEFORE the agent binary so the very
first connection is mTLS-protected.

```bash
# CA pulled from the platform's agent_ca_certificates table
psql -c "SELECT cert_pem FROM agent_ca_certificates
         WHERE name='vaultscan-agent-ca-2026' AND enabled=true" \
  > gateway-ca.pem

scp gateway-ca.pem dc01:/var/lib/vaultscan-agent/
```

**Verification**: `sha256sum gateway-ca.pem` on the host matches the
fingerprint in `agent_ca_certificates.fingerprint`.

## Step 3 — Install + enroll

```bash
sudo vaultscan-agent \
  --gateway https://agent-gateway.eu.vaultscan.zaishield.com \
  --agent-id <uuid-from-step-1> \
  --enroll-token <token-from-step-1> \
  --data-dir /var/lib/vaultscan-agent
```

The agent will:
1. Generate a fresh RSA-2048 keypair.
2. POST `/api/v1/agents/<id>/enroll` with the token + its cert.
3. On success, write `agent.crt`, `agent.key`, `fingerprint` to
   the data dir.
4. Start polling for jobs.

**Verification**: 
- `SELECT status, cert_status FROM agents WHERE id=<id>` → `online` + `issued`
- `SELECT decision FROM agent_mtls_handshakes WHERE agent_id=<id>
   ORDER BY occurred_at DESC LIMIT 1` → `accepted`

## Step 4 — Apply tenant policy

```bash
curl -fsS -X PUT https://api/api/v1/agents/<id>/policy \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "allowed_tools": ["nmap","openvas","nuclei","lynis","bloodhound"],
    "allowed_scopes": ["10.0.0.0/16","corp.example.com"],
    "blocked_scopes": ["10.0.99.0/24"],
    "max_concurrent_jobs": 2,
    "max_cpu_percent": 70,
    "max_memory_percent": 75,
    "scan_window_start": "20:00",
    "scan_window_end": "06:00",
    "days_of_week": ["mon","tue","wed","thu","fri"]
  }'
```

Customer-network constraints belong here, NOT in the cloud scope
guard — Scope Guard is the platform gate; agent policy is the local
gate. Defense in depth.

**Verification**: A job submitted with an out-of-policy target
returns `failed: target ... not in local allowed scope` and the
runner records `ErrToolNotAllowed` for any non-allow-listed binary.

## Step 5 — Emergency-stop drill

Before declaring onboarding complete, exercise the kill switch:

```bash
curl -fsS -X POST https://api/api/v1/agents/<id>/emergency-stop \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"reason":"onboarding drill","scope":"agent"}'
```

Within 30 seconds (the §28.2 SLA) the agent's heartbeat picks up the
pending stop, fires the ack, and halts all running tools.

**Verification**: `SELECT sla_ms FROM agent_emergency_stops
WHERE agent_id=<id> ORDER BY arrival_ts DESC LIMIT 1` returns
< 30000.

## Step 6 — Hand off to the tenant admin

Email the tenant_admin with:
- Agent list (names + status)
- Portal URL (`https://<branded-domain>/agents/ops`)
- Emergency-stop button location (`/agents/ops` → red button)
- Policy editor location (`/agents` → per-agent → Policy tab)
- Their first scheduled scan window

## Audit footer

Each step writes to `audit_logs`:
- `agent.provisioned` (step 1, one per agent)
- `agent.enrolled` (step 3, one per agent)
- `agent.policy_updated` (step 4)
- `agent.emergency_stop_drill` (step 5)

Hand-off email includes the audit_logs id range so the customer's
auditor can verify the onboarding integrity end-to-end.
