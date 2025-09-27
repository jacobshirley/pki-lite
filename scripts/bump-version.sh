#!/bin/bash
# Usage: ./bump-version.sh <new-version>
# Example: ./bump-version.sh patch
# Example: ./bump-version.sh 1.2.3
# Example: ./bump-version.sh major

set -e 

if [ -z "$1" ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 patch"
  echo "Example: $0 1.2.3"
  echo "Example: $0 major"
  echo "Example: $0 premajor --preid=beta"
  exit 1
fi

# Bump version in root package.json
pnpm version --no-git-tag-version $@

# Bump version in all workspaces
pnpm -r exec pnpm version --no-git-tag-version $@

