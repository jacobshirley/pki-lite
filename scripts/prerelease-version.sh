#!/bin/bash
# Usage: ./prerelease-version.sh <new-version>
# Example: ./prerelease-version.sh patch
# Example: ./prerelease-version.sh 1.2.3
# Example: ./prerelease-version.sh major

set -e 

if [ -z "$1" ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 patch"
  echo "Example: $0 1.2.3"
  echo "Example: $0 major"
  exit 1
fi

# Bump version in root package.json
pnpm version --no-git-tag-version $1

# Bump version in all workspaces
pnpm -r exec pnpm version --no-git-tag-version $1

