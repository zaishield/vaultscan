# Scanner-Image Release Procedure

Owns: platform_security_admin.

Whenever a scanner tool publishes a new version (nmap 7.95, nuclei
4.0, etc.) we ship an updated image to the registry. The release
gate is cosign-signed verification; without the signature the
scanner-worker refuses to execute the image (HS-01).

## Pre-conditions

- [ ] You have the active cosign private key (see
      [cosign-key-rotation.md](cosign-key-rotation.md)) — never
      live on a build server; signed in CI via the HSM.
- [ ] You can push to `registry.zaishield.com/vaultscan/scanners`.
- [ ] You have `manage_agents` permission in the API.
- [ ] No active scan is currently using the previous version of
      this tool (check `scan_jobs` where `tools @> '["<tool>"]'`
      and `status IN ('dispatched','running')`).

## Step 1 — Build + sign the new image

In the image-pipeline CI (`.github/workflows/scanner-images.yml`),
or manually:

```bash
TOOL=nmap
VERSION=7.95
docker build -t registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION \
  tools/scanner-images/$TOOL/
docker push registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION

# Sign with the active cosign key.
cosign sign --key cosign-active.key \
  --recursive \
  registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION

# Pull the resulting digest + signature back so the registry row
# matches what the worker will see at runtime.
DIGEST=$(crane digest registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION)
SIG=$(cosign verify --key cosign-active.pub \
       --output-format json \
       registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION \
       | jq -r '.[0].optional.signature')
```

**Verification**: `cosign verify --key cosign-active.pub
<image-ref>` exits 0. The image now carries a valid signature in
the registry.

## Step 2 — Register the new image

```bash
psql <<SQL
INSERT INTO scanner_image_registry
  (tool, image_ref, image_digest, plane, enabled,
   cosign_payload, cosign_signature, cosign_key_id)
VALUES (
  '$TOOL',
  'registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION',
  '$DIGEST',
  'external',   -- or 'internal' / 'both' per the tool
  true,
  '$PAYLOAD_B64',
  '$SIG',
  'cosign-2026-q3'      -- active cosign key id
);

-- Disable the previous version.
UPDATE scanner_image_registry
   SET enabled = false
 WHERE tool = '$TOOL'
   AND image_ref != 'registry.zaishield.com/vaultscan/scanners/$TOOL:$VERSION'
   AND enabled = true;
SQL
```

The `enabled=false` flip on the old row means new scans pick up the
new version on next dispatch. In-flight scans complete on their
existing image — the image registry is consulted at dispatch time,
not on every tool invocation.

**Verification**: `SELECT image_ref, enabled FROM scanner_image_registry
WHERE tool='$TOOL' ORDER BY registered_at DESC LIMIT 5` — the new
row enabled, prior rows disabled.

## Step 3 — Smoke test

Submit one external scan against a benign target (a synthetic
staging tenant we keep for this purpose) using a profile that
includes the updated tool:

```bash
curl -fsS -X POST https://api/api/v1/scans/external \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $STAGING_TENANT" \
  -d '{"profile_code":"external_standard_va",
       "targets":["staging.scan-target.zaishield.com"],
       "region":"eu"}'
```

The scanner-worker pulls the new image, verifies its cosign
signature, runs it. On the way through it logs to
`cosign_verifications`. Expected outcome: `decision = accepted`.

**Verification**:
```sql
SELECT decision, reason, occurred_at
  FROM cosign_verifications
 WHERE image_ref LIKE '%$TOOL:$VERSION'
 ORDER BY occurred_at DESC LIMIT 1;
```
→ `accepted`. If anything else, rollback immediately:
```sql
UPDATE scanner_image_registry SET enabled=true
 WHERE tool='$TOOL' AND image_ref LIKE '%<previous-version>';
UPDATE scanner_image_registry SET enabled=false
 WHERE tool='$TOOL' AND image_ref LIKE '%$VERSION';
```

## Step 4 — Wait the bake period (1h)

For one hour, monitor:
- `vaultscan_scan_jobs_completed_total{status="failed",tool="$TOOL"}`
  rate — should be at baseline.
- `vaultscan_audit_chain_breaks_total` — must stay 0.
- `cosign_verifications` for any `rejected_*` decisions on the new
  image.

If anything spikes → rollback (step 3 paragraph above), file a
ticket, do not proceed.

## Step 5 — Update the parser if the tool output shape changed

Many tool updates change JSON shape (new fields, renamed fields,
changed severity strings). The parser in `internal/parsers/` must
keep accepting the previous shape for at least 24h — agents may
not have the new tool version yet.

```go
// Backwards-compatible accept of both old + new field names.
type nucleiInfo struct {
    Name     string `json:"name"`
    Severity string `json:"severity"`
    // v4.0 renamed `description` to `summary`. Accept either.
    Description string `json:"description"`
    Summary     string `json:"summary"`
}
```

PR the parser change WITH unit tests using both old and new shapes
before promoting the image to active.

## Step 6 — Update parser unit tests + commit

```bash
go test ./backend/internal/parsers/... -run TestParse$Tool
```

Push to the release branch. The `scanner_coverage_test.go`
regression test confirms the Dockerfile + parser still exist.

## Audit footer

Each release writes:
- `scanner.image.registered`  (the new row)
- `scanner.image.deactivated` (the previous row)
- `cosign.verification.accepted` (one per smoke-test scan)

The release ticket links back to the audit row ids.

## Yearly purge

Old, disabled scanner_image_registry rows are kept for 1 year for
forensics (so a finding from 2024 can still surface "this was the
image hash that produced it"). Beyond that:

```sql
DELETE FROM scanner_image_registry
 WHERE enabled = false AND registered_at < now() - INTERVAL '1 year';
```
