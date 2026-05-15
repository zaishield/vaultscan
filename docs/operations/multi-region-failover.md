# Multi-Region Failover

Owns: platform_security_admin + CISO + on-call.

Used when a whole region is unavailable (provider outage, cable
cut, regional regulator order) and we need to shift production
to the standby region. Distinct from disaster recovery — DR
restores a backup; failover routes live traffic to an
already-running peer.

## Pre-conditions

- [ ] The standby region is currently in `vaultscan-prod-<region>-standby`
      mode — Postgres is a streaming replica, scanner farm pods are
      scaled to 0, agent-gateway is reachable but DNS weight is 0.
- [ ] You hold `manage_agents` + `create_tenant` permissions AND a
      break-glass token for `region.failover` issued for this shift.
- [ ] Confidence in the data path: streaming-replication lag must
      be < 60s at the moment of failover. Check:
      ```sql
      SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)
        FROM pg_stat_replication;
      ```
- [ ] Customer status page in standby (`status.zaishield.com`) is
      already updated to "Investigating" — failover is the
      remediation, not the diagnosis.

## Decision tree

| Question | If yes |
|---|---|
| Is the primary region COMPLETELY unreachable? | Full failover |
| Is the primary reachable but flapping? | DO NOT failover — split-brain risk. Use maintenance mode + drain instead |
| Is data integrity in doubt? | Snapshot the primary FIRST, even if it's degraded |

## §FullFailover — primary region completely down

### Step 1 — Confirm + snapshot

1. From the standby region's bastion, confirm primary unreachable:
   `nc -zv api.<region>.vaultscan.zaishield.com 443` should fail.
2. **If reachable AT ALL**, force a final snapshot from the
   replica side:
   ```bash
   psql -h <standby-pg> -c "SELECT pg_create_physical_replication_slot('failover_snapshot')"
   ./tools/scripts/dr-drill.sh --dry-run --snapshot-only
   ```

### Step 2 — Promote the standby Postgres

```bash
kubectl --context=<standby-context> -n vaultscan-data \
  exec postgres-standby-0 -- /scripts/promote.sh
```

The promote script:
1. Waits for any in-flight WAL replay to drain.
2. Runs `pg_promote()` on the standby.
3. Updates the cluster CR to mark this replica as the new primary.
4. Records `ops.region.promoted` in `audit_logs` with the
   replay-lag at promotion time.

**Verification**:
```sql
SELECT pg_is_in_recovery();  -- expect false
```

### Step 3 — Scale up the scanner farm + agent gateway

```bash
kubectl --context=<standby-context> -n vaultscan-control \
  scale deployment/api          --replicas=6
kubectl --context=<standby-context> -n vaultscan-control \
  scale deployment/agent-gateway --replicas=3
kubectl --context=<standby-context> -n vaultscan-scanners \
  scale deployment/scanner-worker --replicas=8
```

Wait for `kubectl rollout status` on each before continuing.

### Step 4 — Re-issue agent CA trust if necessary

If the standby region uses a different agent CA from the failed
region (typical for compliance-segregated deployments), agents
will fail mTLS handshake against the new gateway. Solutions:

1. **Same CA**: nothing to do. Agents simply re-resolve DNS and
   handshake against the new gateway.
2. **Different CA**: agents in the failed region need the new CA
   pushed via the [agent-fleet-onboarding](agent-fleet-onboarding.md)
   step 2 procedure. Coordinate with customer admins.

### Step 5 — Shift DNS

The platform DNS is GeoDNS via Route53 / Cloud DNS. Failover:

```bash
# Route 53 — example
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123 \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.vaultscan.zaishield.com",
        "Type": "A",
        "SetIdentifier": "primary-us",
        "Weight": 0,
        "TTL": 30,
        "ResourceRecords": [{"Value": "<dead-region-ip>"}]
      }
    },{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.vaultscan.zaishield.com",
        "Type": "A",
        "SetIdentifier": "standby-eu",
        "Weight": 100,
        "TTL": 30,
        "ResourceRecords": [{"Value": "<standby-ip>"}]
      }
    }]
  }'
```

TTL is set to 30s for fast cutover. Clients with cached resolution
may stay on the old IP for up to 5 minutes — accept this.

### Step 6 — Verify the new active region

Run the full HS-06 acceptance flow against the new region's API:

```bash
VAULTSCAN_API=https://api.vaultscan.zaishield.com \
  ./tools/scripts/acceptance-smoke.sh
```

Expected outcomes:
- Branding loads ✓
- Audit chain verify-deep clean ✓
- A test tenant can create + activate an engagement ✓
- A test scan completes end-to-end ✓
- Compliance dashboard renders ✓

### Step 7 — Notify customers

Status page → "Identified — failover complete, monitoring".
Per-tenant email automatically goes out to the
`partner_branding.contact_email` for every active tenant.

## §FailbackToOrigin

When the primary region recovers:

1. **Do not** flip DNS back immediately. The new primary has
   diverged from the old primary's data (the time between
   replica-lag and the new traffic).
2. The original-primary becomes the new replica: re-base it
   against the now-promoted standby's stream.
   ```bash
   ./tools/scripts/rebase-as-replica.sh \
     --source=<new-primary> --target=<old-primary>
   ```
3. Once streaming is back in sync (lag < 60s), schedule a
   maintenance window to swap roles back. This is just §FullFailover
   in reverse, with no urgency.

## §MaintenanceDrain — primary flapping

Don't failover. Instead:
1. Enable maintenance mode for writes (HS-05).
2. Wait for in-flight scans to drain.
3. Trigger a graceful primary restart.
4. Disable maintenance.

If the flap recurs more than twice in an hour → upgrade to
§FullFailover.

## Audit footer

Required entries:
- `ops.region.failover_initiated`
- `ops.region.promoted` (auto-written by promote.sh)
- `ops.region.scale_up_complete`
- `ops.region.dns_cut_over`
- `ops.region.failover_complete` (with smoke-test result in payload)

PIR within 5 business days. Customer-impact estimate (number of
tenants affected, downtime per tenant) is required.
