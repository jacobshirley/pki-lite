#!/bin/bash

set -e

NEW_VERSION=$1

if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new-version>"
    exit 1
fi

echo "Generating HTML docs for version: $NEW_VERSION"

pnpm exec typedoc \
    --options typedoc.json \
    --out docs-html/$NEW_VERSION \
    --projectDocuments 'README.md' \
    --projectDocuments 'CONTRIBUTING.md' \
    --projectDocuments 'EXAMPLES.md' \
    --githubPages \
    --includeVersion