#!/usr/bin/env bash
# Refreshes nix/pnpm.json (pnpm version + per-platform hashes) from package.json's
# `packageManager` field. Run this after Renovate bumps pnpm, otherwise `nix develop`
# stops with a "pnpm.json is out of date" message.
#
# Needs: nix, jq.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(jq -r '.packageManager' package.json | sed -n 's/^pnpm@\([^+]*\).*/\1/p')"
[ -n "$VERSION" ] || { echo "package.json has no pnpm@<version> packageManager" >&2; exit 1; }

# nix system -> @pnpm/exe platform package
declare -A PLATFORMS=(
    [x86_64-linux]=linux-x64
    [aarch64-linux]=linux-arm64
    [x86_64-darwin]=darwin-x64
    [aarch64-darwin]=darwin-arm64
)

hashes='{}'
for system in "${!PLATFORMS[@]}"; do
    platform="${PLATFORMS[$system]}"
    url="https://registry.npmjs.org/@pnpm/exe.${platform}/-/exe.${platform}-${VERSION}.tgz"
    echo "prefetching ${url}" >&2
    hash="$(nix store prefetch-file --json "$url" | jq -r .hash)"
    hashes="$(jq --arg s "$system" --arg p "$platform" --arg h "$hash" '.[$s] = {platform: $p, hash: $h}' <<<"$hashes")"
done

jq --arg v "$VERSION" --argjson h "$hashes" -n '{version: $v, systems: $h}' > nix/pnpm.json
echo "wrote nix/pnpm.json for pnpm ${VERSION}" >&2
