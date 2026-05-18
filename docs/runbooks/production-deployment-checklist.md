# Production deployment checklist

Use this list before promoting a build from staging to production.
Every item has a verify-it step. Don't sign off until each is
done.

The intent is operator-runnable: no engineer-only context, every
command is copy-paste'able against a staging or production
environment.

---

## 1. Pre-flight: code health

- [ ] **Unit suite green** (both Go modules)
  ```bash
  cd backend && go test -count=1 ./...
  cd agent   && go test -count=1 ./...
  ```

- [ ] **Integration suite green against a real Postgres**
  ```bash
  cd backend && VAULTSCAN_TEST_DATABASE_URL=postgres://... \
    go test -tags=integration -count=1 ./test/integration/...
  ```

- [ ] **Full GA-readiness gate** (runs every item above + fuzz)
  ```bash
  make ga-verify FUZZTIME=60s   # 7-10 minutes
  ```

---

## 2. Pre-flight: secrets

- [ ] **VAULTSCAN_EVIDENCE_MASTER_KEY is NOT a dev key**
  The platform refuses to boot if it sees a known dev value
  (`evidence.knownDevMasterKeys`). Confirm the value in your
  KMS / vault is a fresh 32-byte random.
  ```bash
  # Compare your env's base64 against the dev-list:
  echo $VAULTSCAN_EVIDENCE_MASTER_KEY | sha256sum
  # Then compare to grep -A1 knownDevMasterKeys backend/internal/evidence/vault.go
  ```

- [ ] **VAULTSCAN_ALLOW_DEV_KEYS is NOT "true"** in production overlays
  ```bash
  kubectl -n vaultscan-prod get configmap api-config -o yaml | grep ALLOW_DEV_KEYS
  # expected: not present, or set to "false"
  ```

- [ ] **JWT signing key is rotated and the verify-only history is set**
  ```bash
  curl https://api.your-domain/.well-known/jwks.json | jq '.keys[] | .kid'
  # expected: at least one key id; current production should have the
  # active key + the just-retired key visible during the rotation window
  ```

- [ ] **Integration signing secrets are rotated for any compromised tenants**
  If you've had a SOC report flagging an integration credential, the
  rotation runbook in `secret-rotation.md` §3 explains the atomic swap.

---

## 3. Migration state

- [ ] **Schema is at HEAD**
  ```bash
  psql -c "SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 5"
  # expected: dirty=false, version matches the last NNNN_ in
  # backend/migrations/. As of writing, head = 0063.
  ```

- [ ] **No partial migrations in flight**
  A `dirty=true` row means a previous deploy bailed mid-migration.
  Investigate before deploying further. The repair procedure is
  database-specific; check with the migration-runner docs.

- [ ] **Backup taken in the last 24h**
  ```bash
  # Replace with your actual backup verification command:
  aws s3 ls s3://your-vaultscan-backups/$(date -u +%Y-%m-%d)/
  ```
  Test the latest backup against the drill in
  `backend/test/integration/backup_restore_drill_test.go` — that
  test's mechanics (pg_dump | psql with checksum verification)
  is the recipe for a real restore exercise.

---

## 4. Audit chain health

- [ ] **VerifyDeep returns first_bad_id=0**
  ```bash
  curl -H "Authorization: Bearer $PLATFORM_ADMIN_TOKEN" \
       https://api.your-domain/api/v1/audit/verify-deep | jq
  # expected: {"first_bad_id":0, "total_rows":NNNN, ...}
  ```
  Any non-zero `first_bad_id` is a chain break and must be
  investigated BEFORE deploy.

- [ ] **Incremental verifier checkpoint is current**
  ```bash
  psql -c "SELECT last_verified_id, last_verified_at, rows_verified_total
             FROM audit_chain_verification_checkpoints WHERE id=1"
  # expected: last_verified_at within the last hour
  ```

- [ ] **Generate the quarterly evidence bundle**
  ```bash
  ./audit-bundle \
    -db $VAULTSCAN_DATABASE_URL \
    -sign-key $(cat /secrets/bundle-signing.key) \
    -output /tmp/$(date -u +%Y-Q%q).tar.gz
  ```
  Store the bundle in your compliance archive. Auditors will ask.

---

## 5. SSRF + inbound HMAC posture

- [ ] **SSRF guard is enabled by default** (no override env set)
  ```bash
  kubectl -n vaultscan-prod get deploy api -o yaml | grep -A1 ALLOW_PRIVATE_HOSTS
  # expected: not present, or set to "false"
  ```

- [ ] **Latest fuzz pass executed against integration package**
  ```bash
  cd backend && go test -fuzz=FuzzValidateOutboundURL -fuzztime=60s \
    ./internal/integrations/
  cd backend && go test -fuzz=FuzzVerifyInbound      -fuzztime=60s \
    ./internal/integrations/
  ```
  60 seconds is a release-gate minimum; 10 minutes is better for
  security-sensitive releases.

---

## 6. RLS posture

- [ ] **Every tenant-scoped table has RLS enabled + forced**
  ```sql
  SELECT n.nspname, c.relname,
         c.relrowsecurity, c.relforcerowsecurity
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE c.relname IN ('findings', 'audit_logs', 'finding_evidence',
                       'scan_jobs', 'assets', 'tenant_data_keys')
     AND n.nspname = current_schema();
  -- expected: rls=true AND force=true for every row
  ```

- [ ] **Cross-tenant RLS test passes against staging**
  ```bash
  cd backend && VAULTSCAN_TEST_DATABASE_URL=<staging> \
    go test -tags=integration -count=1 \
    -run 'TestRLS_TenantCannotReadOtherTenant_(Findings|AuditLogs)' \
    ./test/integration/...
  ```

---

## 7. Operational dependencies

- [ ] **Keycloak (or your IdP) reachable from the API pods**
  ```bash
  kubectl -n vaultscan-prod exec deploy/api -- \
    curl -sf https://keycloak.your-domain/realms/vaultscan/.well-known/openid-configuration > /dev/null
  ```

- [ ] **OpenBao / secrets manager reachable**
  ```bash
  kubectl -n vaultscan-prod exec deploy/api -- \
    curl -sf $VAULTSCAN_OPENBAO_URL/v1/sys/health > /dev/null
  ```

- [ ] **S3 / Ceph evidence bucket is writable**
  ```bash
  # Round-trip a small object with the same creds the API pods use.
  aws --endpoint-url=$VAULTSCAN_S3_ENDPOINT \
      s3 cp /tmp/health-probe s3://vaultscan-evidence/health-probe-$(date +%s)
  aws --endpoint-url=$VAULTSCAN_S3_ENDPOINT \
      s3 rm s3://vaultscan-evidence/health-probe-$(date +%s)
  ```

---

## 8. Smoke test post-deploy

- [ ] **/healthz responds 200**
- [ ] **/readyz reports all components healthy**
- [ ] **/.well-known/jwks.json returns the current active key**
- [ ] **A real user can log in + see their tenant dashboard**
- [ ] **A test scan can be queued** (use an internal staging asset)
- [ ] **The post-deploy load test reports p99 < target**
  ```bash
  go run ./backend/cmd/loadtest \
    -target https://api.your-domain/healthz \
    -workers 25 -duration 30s \
    -max-fail-pct 0.1 -max-p99-ms 250
  ```

---

## 9. Rollback plan

Every promotion to production should have a documented rollback
that can run in under 10 minutes:

- [ ] **Previous image tag is recorded** in your release artifact
- [ ] **`helm rollback` command is tested** in staging
- [ ] **Migration down-files exist for every up that's new in
      this release** (the `TestMigrations_EveryUpHasDown` test
      asserts this; verify by running it)

---

## 10. Communication

- [ ] **Customer-facing release notes drafted**
- [ ] **#vaultscan-deploy Slack channel notified BEFORE deploy starts**
- [ ] **On-call engineer is paged-able for the 30 minutes
      following the deploy**
- [ ] **Post-deploy verification window is scheduled**
      (typical: 1 hour of monitoring before declaring success)

---

When every box is checked: ship it.

If anything in this list is unverifiable on your environment, the
process is wrong — fix the verification before fixing the deploy.
