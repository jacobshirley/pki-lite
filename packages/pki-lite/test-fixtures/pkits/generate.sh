#!/usr/bin/env bash
# Regenerates pkits.ts (NIST PKITS certificates and certification paths for sections 4.8
# to 4.13) used by test/unit/pkits.test.ts.
#
#   ./generate.sh        (rewrites pkits.ts next to this script)
#
# Requires curl, unzip, sha256sum, pdftotext (poppler) and python3. The downloads are
# pinned by hash, so the output is reproducible.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

BASE=https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents
curl -sSfL -o "$WORK/PKITS_data.zip" "$BASE/PKITS_data.zip"
curl -sSfL -o "$WORK/PKITS.pdf" "$BASE/PKITS.pdf"
sha256sum -c - <<EOF
592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665  $WORK/PKITS_data.zip
506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea  $WORK/PKITS.pdf
EOF

mkdir "$WORK/data"
unzip -q "$WORK/PKITS_data.zip" -d "$WORK/data"
pdftotext -layout "$WORK/PKITS.pdf" "$WORK/PKITS.txt"
python3 "$HERE/emit-ts.py" "$WORK/PKITS.txt" "$WORK/data/certs" > "$HERE/pkits.ts"
echo "wrote $HERE/pkits.ts"
