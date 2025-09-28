#!/bin/bash

set -e

NEW_VERSION=${1:-"$(node -p "require('../package.json').version")"}

pnpm exec typedoc \
    --options typedoc.json \
    --out docs-html/$NEW_VERSION \
    --projectDocuments 'README.md' \
    --projectDocuments 'CONTRIBUTING.md' \
    --projectDocuments 'EXAMPLES.md' \
    --githubPages \
    --includeVersion