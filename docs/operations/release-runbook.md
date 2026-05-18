# Release runbook — cutting the first `v*` tag

Procedure for the engineering release manager to cut a tagged
release. Follow this checklist; do not skip steps.

## Pre-flight (engineering)

| # | Item | How |
| --- | --- | --- |
| 1 | CI on `main` is green | `gh workflow view ci.yml --ref main` |
| 2 | `security.yml` on `main` is green | `gh workflow view security.yml --ref main` |
| 3 | `helm-deploy-verify.yml` on `main` is green | smoke-tests the chart against kind |
| 4 | Migration `0056` (last GA migration) applied + tested | `make integration-test` |
| 5 | CHANGELOG.md has a section for the new version | edit `## [Unreleased]` → `## [1.0.0]` + new `## [Unreleased]` |
| 6 | No `TODO(blueprint-ga)` / `XXX` left in `internal/` | `grep -rn "TODO(blueprint-ga)\|XXX" backend/internal/` |
| 7 | `go.mod` + `package.json` deps clean | `go mod tidy && (cd portal && pnpm dedupe)` |

## Cut the tag

```bash
# Pick the version. Semantic Versioning rules:
#   MAJOR.MINOR.PATCH[-pre]
#   - bump MAJOR for breaking changes (API removal, schema field
#     drop, env-var rename)
#   - bump MINOR for backwards-compatible features (new endpoints,
#     new tables, new opt-in flags)
#   - bump PATCH for backwards-compatible bug fixes
#
# First GA release: v1.0.0
VERSION=v1.0.0

# Verify CHANGELOG.md has a section matching this version.
grep -q "^## \[${VERSION#v}\]" CHANGELOG.md || {
  echo "FAIL: CHANGELOG.md has no section for ${VERSION#v}"
  exit 1
}

# Sign the tag (requires the maintainer's GPG/SSH key registered with
# GitHub). Annotated tag with the changelog section as the body.
awk -v ver="${VERSION#v}" '
  $0 ~ "^## \\[" ver "\\]" { capture=1; next }
  capture && /^## \[/ { exit }
  capture { print }
' CHANGELOG.md > /tmp/tag-msg.txt

git tag -s "$VERSION" -F /tmp/tag-msg.txt

# Push the tag — this fires BOTH workflows in parallel:
#   security.yml      → scanner-image-sign-and-pin → digests.json
#                       commit back to main
#   release.yml       → DRAFT GitHub Release with the matching
#                       CHANGELOG section
git push origin "$VERSION"
```

## Verify automated steps

```bash
# Wait for security.yml's scanner-image-sign-and-pin matrix to finish.
gh run watch --workflow=security.yml --exit-status

# Confirm digests.json was committed back to main.
git fetch origin main
git log origin/main --oneline -1 -- tools/scanner-images/digests.json
# expect: a commit from github-actions[bot] with message like
#         "chore(security): populate scanner image digests for v1.0.0"

# Inspect the populated file.
git show "origin/main:tools/scanner-images/digests.json" | jq

# Expect:
# {
#   "version": "v1.0.0",
#   "registry": "registry.zaishield.com/vaultscan/scanners",
#   "digests": {
#     "nmap":   "sha256:abc...",
#     "nuclei": "sha256:def...",
#     ...
#   }
# }
#
# Every tool in tools/scanner-images/<tool>/ MUST appear.
# If any are missing, the GA-gate strict mode (production default)
# will refuse to dispatch scans for that tool.
```

## Publish the release

```bash
# The release.yml workflow opens a DRAFT release. Review the auto-
# generated notes + the CHANGELOG-extracted body, edit if needed,
# then publish.
gh release view "$VERSION" --web

# After clicking Publish:
gh release view "$VERSION" --json url,name,tagName,publishedAt
```

## Post-release verification

```bash
# 1. Pull the chart from the registry + dry-run install the new tag.
helm pull oci://registry.zaishield.com/vaultscan/charts/vaultscan \
  --version "${VERSION#v}" --untar --untardir /tmp/vs-${VERSION}
helm template vaultscan /tmp/vs-${VERSION}/vaultscan \
  -f /tmp/vs-${VERSION}/vaultscan/values-prod.yaml | head -50

# 2. Confirm cosign verifies every scanner image.
for tool in $(ls tools/scanner-images/); do
  img="registry.zaishield.com/vaultscan/scanners/${tool}:${VERSION#v}"
  cosign verify --certificate-identity-regexp \
      "https://github.com/zaishield/vaultscan/.*@refs/tags/${VERSION}$" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$img" >/dev/null && echo "OK: $tool" || echo "FAIL: $tool"
done

# 3. Verify the API binary's --version reports the tag.
docker run --rm registry.zaishield.com/vaultscan/api:${VERSION#v} --version
# expect: vaultscan-api v1.0.0 (commit=<sha>, built=<iso8601>)

# 4. Smoke-test a staging install with the new chart.
make tf-local-up ENV=staging
make tf-local-portforward ENV=staging
curl -s localhost:8080/api/v1/status | jq
# expect: {"version":"v1.0.0","uptime_s":...,"components":{...}}
```

## If something goes wrong

### digests.json wasn't populated

Most likely cause: `security.yml`'s tag trigger isn't firing.

```bash
gh run list --workflow=security.yml --event=push --limit=5
# Look for a run on the tag SHA. If absent:
#  - Check .github/workflows/security.yml has `tags: ["v*"]` under `on.push`
#  - Re-run manually: gh workflow run security.yml --ref "$VERSION"
```

### Cosign signing failed

The keyless signing flow needs the workflow to have
`id-token: write` permission + Sigstore's fulcio + rekor to be
reachable. Check:

```bash
gh run view <run-id> --log | grep -i "cosign\|fulcio\|rekor"
```

If the registry rejects the push, the GitHub Actions service account
needs `write:packages` (GHCR) or the registry-specific equivalent.

### Wrong version in the release notes

Edit the draft release in the GitHub UI before clicking Publish. The
CHANGELOG-extracted body is in the description field; the auto-
generated PR-categorised section is below it.

### Need to retract a release

```bash
gh release delete "$VERSION" --yes        # removes the GitHub release
git push --delete origin "$VERSION"       # deletes the remote tag
git tag -d "$VERSION"                     # deletes the local tag
# IMPORTANT: do NOT delete the digests.json commit on main — it's
# already published and consumers may be pulling it. Cut a NEW
# patch version (v1.0.1) with the fix instead.
```

## Cadence

| Release type | Cadence | Approval |
| --- | --- | --- |
| Patch (`v1.0.x`) | as needed (bug fixes, security) | engineering lead |
| Minor (`v1.x.0`) | every 4-6 weeks | engineering lead + product |
| Major (`vN.0.0`) | when contracts allow breaking changes | board sign-off |

## Coordinated disclosure

If the release fixes a CVE-grade bug, follow `docs/operations/security-disclosure.md`
before pushing the tag — customers need at least 7 days' notice of a
breaking-fix upgrade window.
