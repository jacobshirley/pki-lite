#!/bin/bash

set -e

NEW_VERSION=${1:-"$(node -p "require('../package.json').version")"}

echo "Generating HTML docs for version: $NEW_VERSION"

pnpm exec typedoc \
    --options typedoc.json \
    --out docs-html/$NEW_VERSION \
    --projectDocuments 'README.md' \
    --projectDocuments 'CONTRIBUTING.md' \
    --projectDocuments 'EXAMPLES.md' \
    --githubPages \
    --includeVersion