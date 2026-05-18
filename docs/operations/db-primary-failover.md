# Runbook — DB primary failover

## When to use

The Postgres primary is dead, unreachable, or behaving abnormally
enough that promotion-of-replica is faster than primary recovery.

Distinct from `disaster-recovery.md` (which covers full-region loss)
and `replica-routing.md` (which is the read path).

## Pre-conditions

Verify before promoting:

- A replica exists and is `streaming` (`SELECT * FROM pg_stat_replication`).
- Replica lag is bounded (`SELECT extract(epoch FROM
  (now() - pg_last_xact_replay_timestamp())))`).
- You have the cloud-provider permission to promote (RDS Modify;
  Cloud SQL Failover; Azure PostgreSQL trigger).

If lag > 30 s OR the replica is at minor-version behind primary:
**STOP**. Promotion will lose data. Engage on-call lead + customer
comms.

## Cloud-specific promotion

### AWS RDS

```bash
# Confirm the primary endpoint + replica identifier:
aws rds describe-db-instances --db-instance-identifier vaultscan-primary
aws rds describe-db-instances --db-instance-identifier vaultscan-replica

# Failover (only valid if Multi-AZ — for cross-region replicas use promote-read-replica):
aws rds reboot-db-instance --db-instance-identifier vaultscan-primary --force-failover

# For a cross-region replica:
aws rds promote-read-replica --db-instance-identifier vaultscan-replica
# After promote, the replica's endpoint stays — it just becomes a primary.
```

### GCP Cloud SQL

```bash
gcloud sql instances failover vaultscan-primary --failover-target=zone
# OR for cross-region:
gcloud sql instances promote-replica vaultscan-replica
```

### Azure PostgreSQL Flexible Server

```bash
az postgres flexible-server replica promote \
  --resource-group vaultscan-rg --name vaultscan-replica
```

### Bare metal / on-prem (Patroni)

```bash
patronictl -c /etc/patroni.yml failover --candidate vaultscan-replica
# patronictl will promote + reconfigure the other replicas to follow
# the new primary.
```

## App-side cutover

Once the new primary is up:

```bash
# 1. Update VAULTSCAN_DATABASE_URL (if it points at the old primary
#    hostname). RDS Multi-AZ keeps the DNS the same — no app change
#    needed. Read-replica promote DOES need a DNS change.
kubectl set env -n vaultscan deployment/vaultscan-api \
  VAULTSCAN_DATABASE_URL="postgres://...new-primary..."

# 2. Roll the API + cron-runner + workers (they cache the connection).
for d in vaultscan-api vaultscan-cron-runner vaultscan-scanner-worker \
         vaultscan-analytics-worker vaultscan-agent-gateway; do
  kubectl rollout restart -n vaultscan deployment/$d
done

# 3. Watch for healthy roll:
kubectl rollout status -n vaultscan deployment/vaultscan-api --timeout=180s
```

## After cutover

1. **Verify writes**: submit a smoke scan against the API; tail the
   `audit_logs` table for the new event row.
2. **Stand up a new replica**: the new primary has no replica. Boot
   a fresh one (cloud-specific) so the next failure has somewhere to
   go.
3. **Check the audit chain**: `audit.VerifyDeep` against the new
   primary — confirm the chain wasn't broken by any in-flight
   transactions that didn't make it to the replica.
4. **Customer comms**: 1-paragraph note + ETR to fully-healthy
   posture (= when the new replica is caught up).

## Common pitfalls

- **Forgetting to update VAULTSCAN_DATABASE_REPLICA_URL** — reads
  will still go to the old (now-dead) replica's hostname. Fix
  before rolling.
- **PgBouncer pooling stale connections** — the bouncer's `RECONFIG`
  is needed if it's using a static config. Restart it.
- **Cross-region promote in a residency-pinned tenant** — promoting
  the EU replica to be the new EU primary is fine; promoting it
  to serve US tenants would violate residency. Check
  `tenants.data_region` before re-pointing app traffic.

## Don'ts

- **Do NOT** promote a replica that's >30 s behind without a Sev-1
  data-loss decision from the CTO.
- **Do NOT** delete the old primary until the new one has been
  verified for at least 1 hour.
- **Do NOT** skip standing up the new replica. Running without one
  means the next failure is a full-region loss event.

## Postmortem questions

- Why did the primary fail?
- Was the failover automatic (cloud-managed) or manual?
- What was the total downtime + data-loss window?
- Does the runbook need an update?

## Related

- `disaster-recovery.md` (full region loss)
- `replica-routing.md` (steady-state read path)
- `incident-response.md` (parent classification)
