# Security Incident Commander (IC) guide

**Primary objective:** lead a Sev-1 / Sev-2 security incident from
detection to resolution, owning communication, coordination, and
post-mortem accountability.

This is the IC ROLE — not a person's title. Anyone on the security
on-call rotation can be IC for a given incident.

## What separates this from `customer-escalation.md`

| | Customer escalation | Security IC |
| --- | --- | --- |
| Trigger | Customer-impacting bug | Suspected/confirmed compromise |
| Owner | Engineering on-call | Security on-call |
| Disclosure clock | Status page + customer email | Regulator (72h GDPR Art 33) + customer + board |
| Forensics | Optional | Required + chain-of-custody preserved |
| External coords | CSM + Support | Legal + PR + sometimes law enforcement |

If both apply, security IC is primary; engineering IC reports to them.

## First 30 minutes (the only thing that matters)

| Min | Action | Owner |
| --- | --- | --- |
| 0 | Page the security on-call | Detector |
| 2 | IC accepts page; opens `#sec-inc-YYYYMMDD-<name>` Slack channel | IC |
| 5 | Page secondary IC (always have 2) + scribe | IC |
| 7 | Initial scope: what, when, who, what's confirmed vs hypothesised | IC |
| 10 | Decide: do we kill access? Do we preserve evidence? Both? | IC |
| 15 | First customer-impact assessment: tenants potentially affected | IC + Engineering |
| 20 | Legal awareness — GDPR / HIPAA / PCI clocks start ticking | IC notifies legal |
| 25 | Status page if customer-impacting | CSM (under IC direction) |
| 30 | First SITREP in channel | Scribe |

## Decision tree at minute 10

```
Was customer data accessed by an unauthorized party?
├── YES → "breach" mode: preserve evidence FIRST, then contain
│         (DO NOT just delete the attacker's account — you'll lose forensic trail)
│
└── NO  → "incident" mode: contain immediately, investigate after
```

## Containment playbook

### If a credential is compromised

```bash
# Revoke all sessions for the user:
ADMIN_JWT=$(...)
curl -X POST "$API/api/v1/auth/jwt-keys/rotate" \
  -H "Authorization: Bearer $ADMIN_JWT"
# All JWTs minted under the previous key are now invalid.

# AND specifically for the suspect user:
curl -X POST "$API/api/v1/users/$USER_ID/revoke-all-tokens" \
  -H "Authorization: Bearer $ADMIN_JWT"

# AND disable the account (don't delete — evidence):
curl -X POST "$API/api/v1/users/$USER_ID/suspend" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"reason":"sec-inc-XXXX"}'
```

### If an integration token is compromised

```bash
# Rotate ALL the affected integration's secrets:
./tools/scripts/rotate-secrets.sh integration "$ADMIN_JWT" "$INT_ID"
```

### If a scanner image was tampered

```bash
# Refuse all new dispatches until the next signed image lands:
kubectl set env -n vaultscan deployment/vaultscan-api \
  VAULTSCAN_REQUIRE_PINNED_IMAGES=true
kubectl rollout restart -n vaultscan deployment/vaultscan-api

# Audit which scans have run against the suspect image:
psql "$VAULTSCAN_DATABASE_URL" -c "
  SELECT id, tenant_id, profile, image_ref, started_at
    FROM scan_tasks
   WHERE image_ref LIKE '%<suspect-digest>%'
   ORDER BY started_at DESC LIMIT 50;
"
```

### If the audit chain is broken

This is a P0 incident. The chain breaking means we cannot prove
integrity of any audit row past the break.

1. STOP all writes if possible (set maintenance mode):
   ```bash
   curl -X POST "$API/api/v1/platform/maintenance" \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"enabled":true,"message":"Investigating data integrity"}'
   ```
2. Run `audit.VerifyDeep` to find the exact break point:
   ```bash
   curl -X POST "$API/api/v1/audit/verify-deep" \
     -H "Authorization: Bearer $ADMIN_JWT" | jq
   ```
3. Snapshot the DB immediately:
   ```bash
   make backup-snapshot
   ```
4. Determine: tampering vs corruption vs bug
   - Tampering: tampered rows have valid chain_hash but mismatched
     content — engage legal immediately
   - Corruption: chain_hash itself is bad — likely disk / replication
     issue — restore from backup
   - Bug: same row repeated, ordinal mismatch — engineering issue

## Evidence preservation

If you suspect compromise:

1. **DO NOT delete the attacker's account** — preserves forensics
2. **DO snapshot the cluster** — `velero backup create sec-inc-XX-snap`
3. **DO copy audit logs to a separate bucket** (immutable storage):
   ```bash
   curl -s "$API/api/v1/audit/export?from=2026-01-01T00:00:00Z" \
     -H "Authorization: Bearer $ADMIN_JWT" \
     | gzip > /forensics/sec-inc-XX-audit.ndjson.gz
   aws s3 cp /forensics/sec-inc-XX-audit.ndjson.gz \
     s3://vaultscan-forensics/sec-inc-XX/ --sse aws:kms
   ```
4. **DO note when you start touching production** — every keystroke
   becomes part of the post-mortem timeline

## Communication

### Internal SITREP cadence

- Sev-1: every 30 min into the inc channel
- Sev-2: every 60 min
- Sev-3: every 4 hours

Template in `customer-escalation.md`.

### External (customer) comms

Hold the first customer comm until you have:
1. Confirmed impact (which tenants? what data?)
2. Confirmed containment (the attacker is OUT)
3. Cleared legal (especially if cross-border or regulated)

When you do communicate:
- Be specific about what happened, not vague
- Give them a real ETA for the next update
- Don't speculate on cause until forensics confirm
- Include a request_id / inc_id they can quote in tickets

### Regulator comms (when applicable)

| Regulation | Trigger | Clock |
| --- | --- | --- |
| GDPR Art 33 | EU personal-data breach | 72h to DPA |
| HIPAA Breach Notification | >500 records of PHI | 60 days |
| PCI Incident Response | Card data exposure | 24h to acquirer |
| State breach laws (US) | varies by state | varies; CA = 45 days |

Legal owns the wording. IC owns the timeline.

## Resolution

Incident is RESOLVED when:
- [ ] Attack vector confirmed and closed
- [ ] All compromised credentials rotated
- [ ] Evidence preserved + handed to forensics
- [ ] Customer comms sent (last one says "resolved + when next update")
- [ ] Regulator notification submitted (or `not required` documented)
- [ ] CHANGELOG entry drafted (sanitised — no IoCs, no IP attribution)
- [ ] Post-mortem scheduled within 5 business days

## Post-mortem (within 5 business days)

Blameless format. Attendees: IC, secondary IC, scribe, engineering
lead, CTO, legal observer.

Deliverables:
1. Timeline: detection → containment → resolution
2. Root cause (5 whys)
3. What detected it (good) + what didn't detect it (bad)
4. Action items with owners + dates
5. Lessons for the on-call playbook
6. Sanitised version published to `docs/operations/postmortems/`

## When to call

| Situation | Page |
| --- | --- |
| Suspected unauthorised data access | Security on-call IMMEDIATELY |
| Hash chain break | Security on-call + CTO |
| Cosign signature failure on a production pull | Security on-call |
| Mass account lockouts | Security on-call (might be attack OR config bug) |
| Customer reports their data leaked | Security on-call + CSM |
| Insider threat | Security on-call + HR + legal (in that order) |
| 3rd-party (vendor) breach affecting us | Security on-call + Procurement |

## Related

- `incident-response.md` — parent classification + escalation matrix
- `threat-model.md` — what we built defenses against
- `data-classification.md` — what data is at what sensitivity
- `pentest-engagement-runbook.md` — coordinated red-team engagements
