pnpm exec typedoc \
    --options typedoc.json \
    --out docs-html \
    --projectDocuments 'README.md' \
    --projectDocuments 'CONTRIBUTING.md' \
    --projectDocuments 'EXAMPLES.md' \
    --githubPages \
    --includeVersion

# Replace link in docs

find docs-html -type f -name '*.html' -exec sed -i '' 's/media\/README.md/index.html/g' {} +