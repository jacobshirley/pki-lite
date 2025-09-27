#!/bin/bash
# Usage: ./prerelease-branch.sh

set -e 

# Stage all package.json updates
git add **/package.json

# Get current version
CURRENT_VERSION=$(node -p "require('./package.json').version")

# Commit the changes
git commit -m "release($CURRENT_VERSION): bump version to $CURRENT_VERSION"
