import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, test } from 'vitest'

const packageRoot = resolve(import.meta.dirname, '../..')

/**
 * Runs in a real Node process so the package's own `exports` map is what gets
 * tested, rather than Vite's resolver, which also tries file extensions.
 */
function resolveInNode() {
    const script = `
        const withExtension = 'pki-lite/x509/Certificate.js'
        const withoutExtension = 'pki-lite/x509/Certificate'
        const [a, b] = await Promise.all([
            import(withExtension),
            import(withoutExtension),
        ])
        console.log(JSON.stringify({
            withExtension: import.meta.resolve(withExtension),
            withoutExtension: import.meta.resolve(withoutExtension),
            sameInstance: a === b,
        }))
    `
    const output = execFileSync(
        process.execPath,
        ['--input-type=module', '-e', script],
        { cwd: packageRoot, encoding: 'utf-8' },
    )
    return JSON.parse(output)
}

describe('package exports', () => {
    test('should resolve with and without .js to the same module', () => {
        const result = resolveInNode()

        expect(result.withExtension).toMatch(/\/dist\/x509\/Certificate\.js$/)
        expect(result.withoutExtension).toBe(result.withExtension)
        expect(result.sameInstance).toBe(true)
    })

    test('should map both import styles to existing type declarations', () => {
        const { exports } = JSON.parse(
            readFileSync(resolve(packageRoot, 'package.json'), 'utf-8'),
        )

        for (const pattern of ['./*.js', './*']) {
            expect(exports[pattern].types).toBe('./dist/*.d.ts')
        }
        expect(
            existsSync(resolve(packageRoot, 'dist/x509/Certificate.d.ts')),
        ).toBe(true)
    })
})
