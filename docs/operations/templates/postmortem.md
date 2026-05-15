# Postmortem — INC-<id>

| Field | Value |
|---|---|
| Severity | SEV-1 / SEV-2 / SEV-3 |
| Started  | UTC timestamp |
| Detected | UTC timestamp + how (alert / customer report / engineer noticed) |
| Resolved | UTC timestamp |
| Total impact | duration · # tenants affected · # findings dropped (if any) |
| Customer-facing? | yes / no |
| Regulator-reportable? | yes / no — if yes, jurisdictions + deadlines |
| Authors  | on-call primary, on-call secondary, eng manager |
| Audit row range | first → last audit_logs.id involved |

## Summary (≤ 5 lines, customer-readable)

What happened. What we did. What customers should know.

## Timeline (UTC, one row per event)

| Time | Event | Source |
|------|-------|--------|
| 00:00 | Alert fired: `vaultscan_http_5xx_rate > 0.05` | Alertmanager |
| 00:02 | Primary on-call acked | PagerDuty |
| ...  | ... | ... |

## Detection

- What alert/signal first caught it?
- What was the time-to-detect (TTD)?
- Was the detection adequate? If not — what gap?

## Root cause

Single paragraph. The cause, not the symptom. Use the "5 whys" if
the immediate cause is too shallow.

## Resolution

What action made the problem stop. Reference the runbook step that
applied.

## Impact

- Customer impact: # of tenants, # of failed scans, # of dropped
  events, # of MFA challenges that failed during the window.
- Internal impact: how many hours of on-call time consumed, what
  other work was deferred.
- Data integrity: was `audit_chain_breaks_total` zero throughout?
  was `evidence_chain_of_custody` consistent?

## What went well

Three bullets. Resist the urge to be falsely modest — capturing
what worked teaches the next on-call.

## What went poorly

Three bullets. Be honest. This is the section that earns the team
its credibility with the customer.

## Lucky breaks

What kept this from being worse? Recognising luck is necessary so
we don't mistake it for capability.

## Action items

| # | Action | Owner | Due | Ticket | Severity if not done |
|---|--------|-------|-----|--------|----------------------|
| 1 | ... | name | 2026-MM-DD | LINEAR-### | SEV-1 / SEV-2 |

Every action item must have a ticket. "Improve monitoring" is not
an action item.

## Lessons learned

What did this teach us about the system that we'll apply elsewhere?
This is the section the engineering manager reads when planning
quarterly work.

## Customer communication

- Status page final post (link)
- Per-tenant email body (link to the sent email)
- Public postmortem (if any) — published under
  `https://status.zaishield.com/incidents/<id>` after a 14-day delay

## Sign-off

| Role | Name | Approved at |
|------|------|-------------|
| On-call primary | | |
| Engineering manager | | |
| CISO (SEV-1 only) | | |
| Legal (regulator-reportable only) | | |
