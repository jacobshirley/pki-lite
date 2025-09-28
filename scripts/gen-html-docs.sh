pnpm exec typedoc \
    --options typedoc.json \
    --out docs-html \
    --projectDocuments 'README.md' \
    --projectDocuments 'CONTRIBUTING.md' \
    --projectDocuments 'EXAMPLES.md' \
    --githubPages \
    --includeVersion