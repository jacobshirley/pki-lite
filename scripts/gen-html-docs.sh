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

# Copy to versioned folder
cp -r docs-html docs-html/v$NEW_VERSION