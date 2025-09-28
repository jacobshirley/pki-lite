#!/bin/bash
# Usage: ./prepare-release.sh

set -e 

force_args=()
if [[ " $* " == *" --force=true"* ]]; then
    force_args+=("--force")
fi

# Stage all
git add --all

# Get current version
CURRENT_VERSION=$(node -p "require('./package.json').version")

# Output the current version to use in other steps
echo "$CURRENT_VERSION" > .release-version

# Create a new branch for the release
git checkout -b "release/v$CURRENT_VERSION"

# Commit the changes
git commit -m "release(v$CURRENT_VERSION): prepare"

# Push the branch to the remote repository
git push origin "release/v$CURRENT_VERSION" -u "${force_args[@]}"

if [[ " $* " == *" --create-pr "* ]]; then
    # Create a pull request using GitHub CLI
    PR_TITLE="chore: prerelease $CURRENT_VERSION"
    gh pr create --fill --head "release/v$CURRENT_VERSION" --base master --body "Automated prerelease branch for version $CURRENT_VERSION" || true # Ignore errors if PR already exists
fi
