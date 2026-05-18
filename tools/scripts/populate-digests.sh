#!/usr/bin/env bash
# populate-digests.sh — manual fallback for the CI-driven
# tools/scanner-images/digests.json generation.
#
# When you can: cut a v* release tag and let .github/workflows/
# security.yml > scanner-image-sign-and-pin populate digests.json
# automatically via the cosign-signed image push pipeline.
#
# When you can't (registry creds not yet in CI, offline build, a
# break-glass release): run this script locally to build, sign,
# push, and capture the digests for every tool.
#
# Requirements: docker + cosign + jq + a registry login + a Sigstore
# OIDC token (run `cosign login` first; the keyless flow uses your
# GitHub identity or the local OIDC flow).

set -euo pipefail

REGISTRY="${VAULTSCAN_REGISTRY:-registry.zaishield.com/vaultscan/scanners}"
VERSION="${VAULTSCAN_VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}"
DIGESTS_FILE="${VAULTSCAN_DIGESTS_FILE:-tools/scanner-images/digests.json}"

# Tools to build = every directory under tools/scanner-images/ that
# has a Dockerfile. Stable order so the digests.json diff is readable.
TOOLS=$(find tools/scanner-images -maxdepth 2 -name Dockerfile -printf '%h\n' \
        | sed 's|tools/scanner-images/||' | sort)

# Pre-flight
for cmd in docker cosign jq; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "FAIL: $cmd not in PATH"; exit 1
  }
done

echo "registry: $REGISTRY"
echo "version:  $VERSION"
echo "tools:    $(echo "$TOOLS" | wc -l)"
echo

# Build a fresh JSON document. Atomic write at the end so a half-
# populated file never replaces a working one.
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

cat > "$tmpfile" <<EOF
{
  "version": "$VERSION",
  "registry": "$REGISTRY",
  "digests": {}
}
EOF

for tool in $TOOLS; do
  echo "=== $tool ==="
  img="$REGISTRY/$tool:$VERSION"

  echo "  build..."
  docker build -t "$img" "tools/scanner-images/$tool" >/dev/null

  echo "  push..."
  docker push "$img" >/dev/null

  digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$img" | awk -F'@' '{print $2}')
  if [[ -z "$digest" ]]; then
    echo "  FAIL: no digest captured for $tool"
    exit 1
  fi
  echo "  digest: $digest"

  echo "  cosign sign..."
  cosign sign --yes "$img@$digest" >/dev/null

  # Merge into the JSON.
  jq --arg tool "$tool" --arg digest "$digest" \
    '.digests[$tool] = $digest' "$tmpfile" > "$tmpfile.new"
  mv "$tmpfile.new" "$tmpfile"
done

# Verify the resulting file parses + has every tool.
jq -e '.digests | keys | length > 0' "$tmpfile" >/dev/null

# Atomic write to the real location.
mv "$tmpfile" "$DIGESTS_FILE"
trap - EXIT

echo
echo "✓ $DIGESTS_FILE updated"
echo
echo "next steps:"
echo "  1. Verify every tool got a digest:"
echo "       jq '.digests | length' $DIGESTS_FILE"
echo "  2. Commit:"
echo "       git add $DIGESTS_FILE"
echo "       git commit -m 'chore(security): populate scanner digests for $VERSION'"
echo "  3. Push to the release tag branch."
