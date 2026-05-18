# Runbook — customer escalation / Sev-1 incident response

## When to use

The customer is reporting an actively-impacting issue that warrants
engineering paging. Use this flow regardless of how the report
reached you (support ticket, exec-to-exec ping, Slack DM, Twitter).

## First 15 minutes

| Min | Action |
| --- | --- |
| 0   | Acknowledge to the customer; do NOT promise a timeline |
| 1   | Open an incident channel (`#inc-YYYYMMDD-<short-name>`) |
| 2   | Page the on-call (via PagerDuty / runbook automation) |
| 5   | Pull metrics: `vaultscan_request_total`, `_errors`, `_latency` filtered by their tenant_id |
| 10  | Determine: is this tenant-specific or platform-wide? |
| 15  | Post first SITREP into the inc channel (what, when, who, what we know) |

## Severity assignment

| Sev | Definition | Response |
| --- | --- | --- |
| 1 | Platform down or data loss | Page CTO + Head of Security |
| 2 | Major feature broken; multiple tenants impacted | Page on-call lead |
| 3 | Single-tenant impact OR workaround exists | Eng investigation in business hours |
| 4 | Cosmetic / minor | Backlog |

Down-grading mid-incident is allowed but requires explicit
sign-off in the inc channel.

## Communication template

Post in `#inc-…` every 30 minutes during a Sev 1/2, hourly during Sev 3:

```
SITREP — <UTC time>

Status: investigating | mitigated | resolved
Impact: <which tenants, which features, % users affected>
Current theory: <leading hypothesis>
Next action: <single concrete next step + owner + ETA>
Customer comms: <last contact + next>
```

### Customer-facing comms template

```
Subject: [Update] [Inc <id>] — VaultScan service status

Hi [customer],

We are currently investigating an issue affecting <feature>. Started
<UTC time>.

Impact: <one sentence>
Current status: <investigating | mitigated | resolved>
Next update: in <interval>

We will post all updates at https://status.zaishield.com.

— VaultScan ops
```

Do NOT include internal hostnames, IPs, or stack traces in customer-
facing comms.

## Investigation runbooks

Reach for the right one BEFORE you start ad-hoc debugging:

| Symptom | Runbook |
| --- | --- |
| 5xx spike | `incident-response.md` §API |
| DB queries hanging | `incident-response.md` §DB + `replica-routing.md` |
| Replica lag | `replica-routing.md` |
| Scanner stuck | `scanner-job-stuck-pending.md` |
| WAF traffic anomaly | `waf-rate-limit-storm.md` |
| Autoscaler oscillating | `cluster-autoscaler-thrash.md` |
| Audit chain break | `incident-response.md` §AuditTamper |
| KEK / DEK error | `kek-dek-rotation.md` |
| Agent fleet disconnect | `incident-response.md` §AgentFleet |
| Suspected breach | `incident-response.md` §Breach (engage legal IMMEDIATELY) |
| Kyverno block | `kyverno-policy-violations.md` |

## During the incident

- **One incident commander** — usually the on-call lead. Their job
  is comms + delegation, NOT keyboard work.
- **One scribe** — captures the timeline in real time.
- **Engineers** — execute the runbook tasks.
- Do NOT debug in production unless the IC explicitly approves.
  Spin up a clone if you can.
- Every command you run goes in the inc channel: `> kubectl ...`

## Resolution criteria

- Customer-facing symptom gone (verified by the impacted tenant or
  by replaying their last failing request)
- Metrics back to baseline for >10 min
- A follow-up issue (or hotfix PR) is tracked
- The CHANGELOG entry is drafted if user-visible

## Post-mortem

Within 48 hours of resolution:
1. Schedule a blameless post-mortem (60 min, all participants)
2. Document in `docs/operations/postmortems/<inc-id>.md`
3. Track action items in GitHub issues, tagged `postmortem-<inc-id>`
4. Publish a sanitised customer-facing post-mortem if Sev 1/2 + customer-facing

## Compliance hooks

If the incident involved:
- **Personal data**: notify the DPO within 72 hours per GDPR Art. 33
- **Health data**: HIPAA breach-notification clock starts (60 days)
- **Card data**: PCI incident response per `incident-response.md` §PCI
- **Audit chain integrity break**: SOC2 control failure — flag for
  the auditor

## Related

- `incident-response.md`
- `on-call.md`
- `release-runbook.md` (for the hotfix release path)
