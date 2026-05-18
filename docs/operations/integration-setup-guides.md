# Integration setup guides

Customer-facing setup walkthroughs for each integration type
VaultScan ships. Each guide lives in its own section; copy the
relevant one into your customer onboarding pack or surface via
the in-app integration wizard.

## Jira

### What this integration does

Pushes VaultScan findings into Jira issues. New finding → new ticket
(by default in your configured project, with severity → priority
mapping). Finding status changes (triaged / remediated) update the
issue. Closed VaultScan findings transition the Jira issue.

### Customer prerequisites

- Jira Cloud OR Jira Server with REST API v3 reachable
- A Jira API token (Atlassian → Account Settings → Security → API tokens)
- A Jira project with the issue type you want to use (Bug / Task / Vulnerability)
- The Jira account creating the token needs `create issue` + `transition` permissions on the project

### Setup

1. In VaultScan: Settings → Integrations → New → Jira
2. Fill in:
   - **API URL**: `https://YOUR-DOMAIN.atlassian.net`
   - **Email**: the Jira account that owns the API token
   - **API Token**: paste the token from Atlassian
   - **Project Key**: e.g. `SEC`, `INFRA`, etc.
   - **Issue Type**: must exist in the project (default `Task`)
   - **Severity → Priority mapping** (optional; defaults to Critical→Highest, High→High, Medium→Medium, Low→Low, Info→Lowest)
3. Click **Test** — VaultScan will POST a `vaultscan.test` event and confirm 2xx
4. Save

### Verifying it works

Trigger a new finding (run a scan against a known-vulnerable target).
Within 30 seconds you should see a Jira issue created with:
- Summary = finding title
- Description = finding detail + asset + scanner
- Labels = `vaultscan`, `severity-<level>`, `<scanner>`

### Common issues

| Symptom | Cause | Fix |
| --- | --- | --- |
| 401 on test | API token wrong / revoked | Generate a new token |
| 403 on test | Account lacks project permission | Grant `create issue` in the project's permission scheme |
| 404 on test | Project key typo | Confirm via Jira `projects` API call |
| Issues created but not transitioned | Workflow transition IDs differ | Configure transition IDs in advanced settings |

---

## Slack

### What this integration does

Posts findings into a Slack channel (your choice). Configurable
severity threshold (e.g. "post Critical + High only"). Optional
@-mention for Sev 1.

### Customer prerequisites

- A Slack workspace
- A Slack incoming webhook URL (Apps → Incoming Webhooks → Add to channel)

### Setup

1. In Slack: create the incoming webhook for the channel you want
   findings posted to. Copy the URL (`https://hooks.slack.com/services/T.../B.../...`).
2. In VaultScan: Settings → Integrations → New → Slack
3. Fill in:
   - **Webhook URL**: paste from Slack
   - **Min severity**: e.g. `high` (anything below this won't post)
   - **Mention user / group** (optional): e.g. `<!subteam^S0123456>` for an oncall group
4. Click **Test**, then Save.

### Common issues

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no_service` | Webhook URL revoked | Create a new webhook in Slack |
| `channel_not_found` | Channel deleted | Recreate or pick another |
| `invalid_payload` | Payload structure changed | Update VaultScan to latest minor |

---

## GitHub Issues

### What this integration does

Opens GitHub issues for findings. Per-repo configuration. Optional
SARIF push for findings that map to source-code files.

### Customer prerequisites

- A GitHub Personal Access Token (Settings → Developer settings → Tokens)
  with `repo` scope (or `public_repo` for a public repo)
- The repo's full name (`owner/repo`)

### Setup

1. Generate a PAT (fine-grained recommended).
2. In VaultScan: Settings → Integrations → New → GitHub
3. Fill:
   - **Token**: the PAT
   - **Owner**: GitHub org / username
   - **Repo**: repo name
   - **Labels** (optional): comma-separated, e.g. `security,vulnerability`
   - **Emit SARIF on push** (toggle): pushes to GitHub Advanced Security if enabled
4. Test + save.

### SARIF push

If "Emit SARIF" is on, every scan also POSTs a SARIF v2.1.0
document to `POST /repos/{owner}/{repo}/code-scanning/sarifs`. The
endpoint at `/api/v1/findings/export.sarif` returns the same
document on demand.

### Common issues

| Symptom | Cause | Fix |
| --- | --- | --- |
| 401 | Token expired / lacks scope | Regenerate with `repo` scope |
| 422 (SARIF) | GHAS not enabled on the repo | Enable in repo Settings → Code security |
| Rate-limited | High-volume scans hitting GitHub's secondary rate limits | Add `delay_between_pushes` in advanced settings |

---

## GitLab Issues

### What this integration does

Same as GitHub but for GitLab. Self-hosted and gitlab.com both supported.

### Setup

1. In GitLab: Settings → Access Tokens → Create token with `api` + `read_repository` scopes
2. In VaultScan: Settings → Integrations → New → GitLab
3. Fill:
   - **API URL**: `https://gitlab.com/api/v4` (or your self-hosted URL)
   - **Token**: from step 1
   - **Project ID**: numeric ID from project Settings → General
   - **Labels** (optional)
4. Test + save.

---

## ServiceNow (ITSM)

### What this integration does

Opens Incident records (or Vulnerability Response items if you have
the SecOps module) for findings.

### Setup

1. In ServiceNow: create an integration user account with the
   `itil` role. Generate a basic-auth credential (or OAuth client).
2. In VaultScan: Settings → Integrations → New → ServiceNow
3. Fill:
   - **Instance URL**: `https://your-instance.service-now.com`
   - **Username** / **Password** (or OAuth client_id/secret)
   - **Table**: `incident` (default) or `sn_vul_vulnerable_item` (SecOps)
   - **Category / Subcategory** mapping
4. Test + save.

### Common issues

| Symptom | Cause | Fix |
| --- | --- | --- |
| 401 / 403 | Account lacks `itil` role | Add it via User Administration |
| 400 on create | Required field missing | Map the field in advanced settings |
| Records created but Incident form fields blank | Field naming differs in custom instances | Use ServiceNow Studio to inspect the table schema |

---

## SIEM (generic syslog / CEF)

### What this integration does

Forwards every audit event + every finding to your SIEM as CEF over
TCP / UDP / TLS.

### Setup

1. In your SIEM: create a receiver for the CEF format on a port
   reachable from VaultScan.
2. In VaultScan: Settings → Integrations → New → SIEM
3. Fill:
   - **Host** / **Port** / **Protocol** (tcp/udp/tls)
   - **TLS** (toggle, with CA cert upload if self-signed)
   - **Event filter** (optional): regex on event type to forward
4. Test + save.

### Verifying

Run `curl $API/api/v1/audit/verify` — the event WILL be forwarded
to your SIEM. Confirm receipt within 30 s.

---

## PagerDuty

### What this integration does

Opens PagerDuty incidents for findings above a configured severity
threshold. De-duplicates within a 24h window by finding fingerprint.

### Setup

1. In PagerDuty: Services → New Service → Integration Type: Events API v2.
2. Copy the integration key.
3. In VaultScan: Settings → Integrations → New → PagerDuty
4. Fill the integration key + min severity. Test + save.

---

## Inbound webhooks (your-system → VaultScan)

If you want YOUR system (CI pipeline, IaC tool, custom script) to
push events INTO VaultScan, configure an inbound webhook integration.

### Setup

1. In VaultScan: Settings → Integrations → New → Webhook (inbound)
2. VaultScan generates an HMAC signing secret. Copy + store securely.
3. In your system: POST to `https://api.vaultscan.zaishield.com/api/v1/integrations/<id>/inbound` with:
   - Header `X-Vaultscan-Timestamp`: UNIX seconds
   - Header `X-Vaultscan-Signature`: `sha256=<hex>` where the
     digest is `HMAC-SHA256(secret, "<ts>.<body>")`
   - JSON body: your event payload
4. The receiver returns 200 on accepted (HMAC verified) or
   `signature_mismatch` / `timestamp_skew` on rejected.

See `inbound-webhooks.md` for the full HMAC reference + rotation procedure.

---

## Custom

If you need an integration we don't ship: use the **Generic Webhook**
type (outbound) — VaultScan POSTs a JSON payload to your URL on
every matching event. Schema documented at `docs/api/openapi.yaml#/components/schemas/IntegrationEvent`.

## Related

- `inbound-webhooks.md` — HMAC reference
- `marketplace.md` (when added) — for partner-published integrations
- `internal/integrations/service.go` — engineering reference
