#!/usr/bin/env bash
# Regenerates the OpenSSL-produced DER corpus (corpus.ts) used by test/unit/openssl-corpus.test.ts.
#
#   ./generate.sh        (rewrites corpus.ts next to this script)
#
# Requires an `openssl` (3.x) on PATH. Keys are random, so regenerating changes every
# file; the committed corpus is only the output of one run. After regenerating, run
# the corpus test and update its KNOWN_ISSUES list if results changed.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
AUDIT="$(mktemp -d)"; export AUDIT
for part in "$HERE"/generate/0*.sh; do echo "== $(basename "$part")"; bash "$part"; done
bash "$HERE/generate/emit-ts.sh" "$AUDIT/corpus" > "$HERE/corpus.ts"
echo "wrote $HERE/corpus.ts"; rm -rf "${AUDIT:?}"
