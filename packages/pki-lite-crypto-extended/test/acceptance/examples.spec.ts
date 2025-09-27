import { describe, expect, test } from 'vitest'

const examples = ['usage']

function captureLogs() {
    const stdout: string[] = []
    const stderr: string[] = []

    const originalConsole = globalThis.console
    //@ts-expect-error
    globalThis.console = {
        log: (...args: any[]) => {
            stdout.push(args.map((a) => String(a)).join(' ') + '\n')
        },
        info: (...args: any[]) => {
            stdout.push(args.map((a) => String(a)).join(' ') + '\n')
        },
        warn: (...args: any[]) => {
            stderr.push(args.map((a) => String(a)).join(' ') + '\n')
        },
        error: (...args: any[]) => {
            stderr.push(args.map((a) => String(a)).join(' ') + '\n')
        },
        debug: (...args: any[]) => {
            stdout.push(args.map((a) => String(a)).join(' ') + '\n')
        },
        trace: (...args: any[]) => {
            stdout.push(args.map((a) => String(a)).join(' ') + '\n')
        },
        // Keep other console methods if needed
        assert: originalConsole.assert.bind(originalConsole),
    }

    const stripAnsi = (str: string) =>
        str.replace(
            // eslint-disable-line @typescript-eslint/no-explicit-any
            // eslint-disable-next-line no-control-regex
            // https://stackoverflow.com/questions/25245716/remove-all-ansi-colors-styles-from-strings
            // eslint-disable-next-line no-control-regex
            /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g,
            '',
        )

    return {
        restore: () => {
            globalThis.console = originalConsole
        },
        getLogs() {
            return {
                stdout: stripAnsi(stdout.join('')),
                stderr: stripAnsi(stderr.join('')),
            }
        },
    }
}

describe.sequential('Examples', () => {
    for (const exampleFile of examples) {
        test(`${exampleFile}`, async () => {
            const { restore, getLogs } = captureLogs()

            await import(`../../examples/${exampleFile}.ts`)

            expect(getLogs().stderr).toBe('')
            expect(getLogs().stdout).toMatchSnapshot()
            restore()
        })
    }
})
