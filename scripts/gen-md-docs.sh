#!/bin/bash

set -e

# Get latest version from package.json
NEW_VERSION=$(node -p "require('./package.json').version")
echo "Generating docs for version: $NEW_VERSION"

# Update absolute doc links to versioned path
find . -type f -name '*.md' -exec sed -i "s|https://jacobshirley.github.io/pki-lite/v[0-9a-zA-Z._-]*|https://jacobshirley.github.io/pki-lite/v$NEW_VERSION|g" {} +

# Generate markdown docs
pnpm exec typedoc --options typedoc.json --plugin typedoc-plugin-markdown --readme none && pnpm format
