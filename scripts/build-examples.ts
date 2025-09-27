import fs from 'fs/promises'

let markdown = `# PKI-Lite Examples

This directory contains example scripts demonstrating how to use the PKI-Lite library.

`

const examples = await fs.readdir(import.meta.dirname + '/../examples')
for (const example of examples) {
    if (example.endsWith('.ts')) {
        const exampleSrc = await fs.readFile(
            import.meta.dirname + `/../examples/${example}`,
            'utf-8',
        )
        const exampleTitleStart = exampleSrc.indexOf('//')
        const exampleTitleEnd = exampleSrc.indexOf('\n', exampleTitleStart)
        const exampleTitle =
            exampleTitleStart !== -1
                ? exampleSrc
                      .substring(exampleTitleStart + 2, exampleTitleEnd)
                      .trim()
                : 'Untitled Example'
        const exampleContent = exampleSrc.substring(exampleTitleEnd + 1).trim()

        markdown += `## ${exampleTitle}\n\n\`\`\`typescript\n${exampleContent}\n\`\`\`\n`
    }
}

await fs.writeFile(import.meta.dirname + '/../EXAMPLES.md', markdown, 'utf-8')
