#!/bin/bash
# Usage: ./bump-version.sh <new-version>
# Example: ./bump-version.sh patch
# Example: ./bump-version.sh 1.2.3
# Example: ./bump-version.sh major

set -e 

if [ -n "$1" ]; then
  # Bump version in root package.json
  npm version --no-git-tag-version $@

  # Bump version in all workspaces
  pnpm -r exec npm version --no-git-tag-version $@

  # Get the new version from root package.json
  NEW_VERSION=$(node -p "require('./package.json').version")

  # Make sure all packages pdf-lite* depend on latest versions of other pdf-lite* packages

  echo "Updating all pdf-lite* dependencies to version $NEW_VERSION"

  find . -name 'package.json' -not -path '*/node_modules/*' | while read -r pkg_file; do
    # Only update if there are pdf-lite* dependencies
    if grep -q '"pdf-lite' "$pkg_file"; then
      tmp_file=$(mktemp)
      node -e "
        const fs = require('fs');
        const pkg = JSON.parse(fs.readFileSync('$pkg_file', 'utf8'));
        const newVersion = '$NEW_VERSION';
        ['dependencies', 'devDependencies'].forEach(depType => {
          if (pkg[depType]) {
            Object.keys(pkg[depType]).forEach(dep => {
              if (dep.startsWith('pdf-lite')) {
                const initialChar = pkg[depType][dep][0];
                if (['^', '~', '>', '<', '='].includes(initialChar)) {
                  pkg[depType][dep] = initialChar + newVersion;
                } else {
                  pkg[depType][dep] = newVersion;
                }
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
fi

# Update lockfile
pnpm install --lockfile-only
