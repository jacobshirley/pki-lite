#!/usr/bin/env bash
# Regenerates limbo.ts (the x509-limbo test cases pki-lite runs, with their certificates
# and CRLs) used by test/unit/x509-limbo.test.ts.
#
#   ./generate.sh        (rewrites limbo.ts next to this script)
#
# Requires curl, sha256sum and python3. The download is pinned by commit and hash, so the
# output is reproducible.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

COMMIT=519f4bcf6a31d20e1b7011a0586e233dbbd3e732
curl -sSfL -o "$WORK/limbo.json" \
    "https://raw.githubusercontent.com/C2SP/x509-limbo/$COMMIT/limbo.json"
sha256sum -c - <<EOF2
56799cefd65fc9e0bdb9cb0f97fce6734533b45df3de4fc17fdc7b7b79654fca  $WORK/limbo.json
EOF2

python3 -I "$HERE/emit-ts.py" "$WORK/limbo.json" "$COMMIT" > "$HERE/limbo.ts"
echo "wrote $HERE/limbo.ts"
