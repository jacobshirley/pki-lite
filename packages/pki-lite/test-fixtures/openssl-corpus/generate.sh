#!/usr/bin/env bash
# Regenerates the OpenSSL-produced DER corpus used by test/node/openssl-corpus.test.ts.
#
#   ./generate.sh [output-dir]      (default: this directory)
#
# Requires an `openssl` (3.x) on PATH. Keys are random, so regenerating changes every
# file; the committed corpus is only the output of one run. After regenerating, run
# the corpus test and update its KNOWN_ISSUES list if results changed.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(cd "${1:-$HERE}" && pwd)"
AUDIT="$(mktemp -d)"; export AUDIT
for part in "$HERE"/generate/0*.sh; do echo "== $(basename "$part")"; bash "$part"; done
for d in cert csr crl key cms p12 ocsp; do mkdir -p "$OUT/$d"; cp "$AUDIT/corpus/$d/"* "$OUT/$d/" || echo "WARNING: no $d output"; done
echo "corpus written to $OUT"; rm -rf "${AUDIT:?}"
