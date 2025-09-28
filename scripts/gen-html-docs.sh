#!/bin/bash

set -e

# Get latest version from package.json
NEW_VERSION=$(node -p "require('./package.json').version")
echo "Generating docs for version: $NEW_VERSION"

pnpm exec typedoc \
    --options typedoc.json \
    --out docs-html \
    --projectDocuments 'README.md' \
    --projectDocuments 'CONTRIBUTING.md' \
    --projectDocuments 'EXAMPLES.md' \
    --githubPages \
    --includeVersion

# Update absolute doc links to versioned path
find docs-html -type f -name '*.html' -exec sh -c 'sed -i "" "s|https://jacobshirley.github.io/pki-lite|https://jacobshirley.github.io/pki-lite/v$NEW_VERSION|g" "$0"' {} \;

# Copy to versioned folder
rsync -a docs-html/ docs-html/v$NEW_VERSION/