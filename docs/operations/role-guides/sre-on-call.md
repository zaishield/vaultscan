# SRE / on-call guide

**Primary objective:** keep production within SLO. Detect, contain,
resolve, post-mortem. Don't be heroic — use the runbooks.

This is the on-call ROLE handbook. The per-incident runbooks
(incident-response.md + per-symptom files) are what you read
DURING an incident.

## On-call rotation

| | Hours | Pager weight |
| --- | --- | --- |
| Primary | 24×7 for the week | All P1/P2 pages |
| Secondary | Backup | If primary doesn't ack within 5 min |
| Tertiary (CTO / Eng lead) | Backup of backup | If primary + secondary don't ack within 15 min |

Handoff: 9am UTC every Monday. Outgoing primary briefs the incoming
on:
- Open incidents (none should be open at handoff)
- Recent unusual signals
- Scheduled maintenance in the next week
- Any "weird stuff to watch for" (recently shipped feature)

## What you do daily

```bash
# Morning check (5 min):
./tools/scripts/morning-check.sh   # or the per-cloud equivalent

# Expected output: all green. Anything red → triage IMMEDIATELY.
```

## What you do during a page

### Step 0 — Acknowledge

PagerDuty: ack within 5 minutes. Or it escalates.

### Step 1 — Triage in <10 min

| Question | Answer determines |
| --- | --- |
| Is the platform up at all? | Sev 1 if no, Sev 2-3 otherwise |
| What % of customers are affected? | Sev priority |
| Is data integrity at risk? | If yes → Security IC takes over (see `security-incident-commander.md`) |
| Is there an active customer escalation? | Loop in CSM (see `customer-escalation.md`) |

### Step 2 — Open the incident channel

`#inc-YYYYMMDD-<short-name>` Slack channel. Even Sev-3 gets one
so the timeline is recoverable.

### Step 3 — Pick the right runbook

```text
5xx spike                 → incident-response.md §API
DB queries hanging        → incident-response.md §DB + replica-routing.md
Replica lag spike         → replica-routing.md
DB primary failure        → db-primary-failover.md
Scanner stuck             → scanner-job-stuck-pending.md
WAF traffic anomaly       → waf-rate-limit-storm.md
Autoscaler oscillating    → cluster-autoscaler-thrash.md
Audit chain break         → security-incident-commander.md (P0)
KEK / DEK error           → kek-dek-rotation.md
Agent fleet disconnect    → incident-response.md §AgentFleet
Kyverno block             → kyverno-policy-violations.md
Customer-impacting Sev1   → customer-escalation.md
Suspected breach          → security-incident-commander.md (P0)
```

### Step 4 — Communicate

SITREP every 30 min (Sev 1), 60 min (Sev 2), 4h (Sev 3). Template
lives in `customer-escalation.md`.

### Step 5 — Resolve

Resolution criteria (must ALL hold):
- Customer-facing symptom gone
- Metrics back to baseline for >10 min
- A fix-forward issue is tracked
- CHANGELOG entry drafted if user-visible

### Step 6 — Post-mortem

Within 48 hours. Blameless. See `customer-escalation.md` §Post-mortem.

## SLO recap (Blueprint §29)

| SLO | Target | How measured |
| --- | --- | --- |
| API availability | 99.9% rolling 28-day | `vaultscan:api_request_success_ratio:5m` |
| API P95 latency | < 500 ms | `vaultscan:api_request_latency_p95:5m` |
| API P99 latency | < 1500 ms | `vaultscan:api_request_latency_p99:5m` |
| Emergency-stop SLA | 95% < 30s | `vaultscan_emergency_stop_sla_ms` p95 |
| Audit chain integrity | 100% | `vaultscan_audit_chain_breaks_total == 0` |
| Replica lag | < 5 s steady-state | `vaultscan_db_replica_lag_seconds` |
| Scan job dispatch latency | < 60 s p95 | `vaultscan_scan_dispatch_latency_seconds` |

Burn-rate alerts fire on SLO consumption:
- Page when 2h burn rate would exhaust the monthly budget in <1 day
- Ticket when 24h burn would exhaust the monthly budget in <7 days

## Tools you have

```bash
# Cluster:
kubectl                              # the right context per-env
k9s                                  # interactive TUI
stern -n vaultscan -l app=...        # multi-pod log tail

# Database:
psql "$VAULTSCAN_DATABASE_REPLICA_URL"      # read-only queries
psql "$VAULTSCAN_DATABASE_URL"              # ONLY for runbook-prescribed writes

# Observability:
prometheus URL                       # query the cluster's Prometheus
grafana URL                          # the on-call dashboard
jaeger URL                           # tracing

# Platform:
curl ... /api/v1/platform/maintenance      # toggle maintenance mode
./tools/scripts/dr-drill.sh                # weekly DR validation
./tools/scripts/rotate-secrets.sh           # secret rotation
./tools/scripts/local-cluster.sh           # for local repro
make backup-snapshot                       # ad-hoc DB snapshot
```

## What you DON'T do (escalate instead)

| Action | Who |
| --- | --- |
| Hard-delete tenant data | Engineering + legal sign-off |
| Roll back a release in <1h post-deploy | Engineering lead (verify rollback is safer than fix-forward) |
| Modify customer billing | Finance |
| Talk to customer in detail about an incident | CSM (you provide facts; CSM owns the conversation) |
| Engage law enforcement | CTO + legal |
| Disclose to a regulator | Legal owns wording; you own timeline |
| Modify Kyverno / RBAC policies | Security team |

## Knowledge base — minimum to memorise

| Topic | Doc |
| --- | --- |
| Severity classification | `incident-response.md` |
| Per-symptom playbooks | (all the runbooks above) |
| Architecture | `ARCHITECTURE.md` |
| Threat model | `threat-model.md` |
| Data classification | `data-classification.md` |
| Disaster recovery | `disaster-recovery.md` |
| DR drill | `restore-verify-drill.md` |
| Capacity model | `capacity-planning.md` |

## Quarterly rituals

| Quarter | What |
| --- | --- |
| Q1 | Refresh DR drill — verify backup→restore→verify-deep on fresh staging cluster |
| Q2 | Refresh capacity numbers — re-run `capacity-validation-runbook.md` k6 |
| Q3 | Threat-model walk + refresh `threat-model.md` |
| Q4 | Runbook audit — pick 3 runbooks and walk them end-to-end as if in incident |

## Useful aliases

```bash
alias vs-prod-logs='kubectl -n vaultscan logs -l app=vaultscan-api --tail=200'
alias vs-prod-readyz='curl -s https://api.vaultscan.zaishield.com/readyz'
alias vs-prod-status='curl -s https://api.vaultscan.zaishield.com/api/v1/status | jq'
alias vs-prod-pods='kubectl -n vaultscan get pods --field-selector=status.phase!=Running'
alias vs-prod-cron='kubectl -n vaultscan logs -l app=vaultscan-cron-runner --tail=100 | grep -E "^|FAIL"'
```

## When to wake the CTO

- Sev 1 active >2 hours
- Audit chain break (immediately)
- Suspected breach
- Customer threatens contract termination
- Regulatory disclosure clock starts
- Multi-region failure
- You're not sure what to do and the runbook doesn't cover it

It is ALWAYS better to wake them and be wrong than not wake them
and be right.
