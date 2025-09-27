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

# Get the new version from root package.json
NEW_VERSION=$(node -p "require('./package.json').version")

# Make sure all packages pki-lite* depend on latest versions of other pki-lite* packages

echo "Updating all pki-lite* dependencies to version $NEW_VERSION"

find . -name 'package.json' -not -path '*/node_modules/*' | while read -r pkg_file; do
  # Only update if there are pki-lite* dependencies
  if grep -q '"pki-lite' "$pkg_file"; then
    tmp_file=$(mktemp)
    node -e "
      const fs = require('fs');
      const pkg = JSON.parse(fs.readFileSync('$pkg_file', 'utf8'));
      const newVersion = '$NEW_VERSION';
      ['dependencies', 'devDependencies', 'peerDependencies'].forEach(depType => {
        if (pkg[depType]) {
          Object.keys(pkg[depType]).forEach(dep => {
            if (dep.startsWith('pki-lite')) {
              pkg[depType][dep] = newVersion;
            }
          });
        }
      });
      fs.writeFileSync('$tmp_file', JSON.stringify(pkg, null, 2) + '\n');
    "
    mv "$tmp_file" "$pkg_file"
    echo "Updated $pkg_file"
  fi
done

echo "Version bump completed successfully to $NEW_VERSION"
