#!/bin/bash

set -e

# Get latest version from package.json
MAJOR_VERSION=$(node -p "require('./package.json').version.split('.')[0]")
echo "Generating docs for version: $MAJOR_VERSION"

# Update absolute doc links to versioned path
find . -type f -name '*.md' -exec sed -i "s|https://jacobshirley.github.io/pki-lite/v[0-9a-zA-Z._-]*|https://jacobshirley.github.io/pki-lite/v$MAJOR_VERSION|g" {} +

# Generate markdown docs
pnpm exec typedoc --options typedoc.json --plugin typedoc-plugin-markdown --readme none && pnpm format
