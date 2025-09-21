import { describe, expect, test } from 'vitest'

const examples = [
    'crl-request',
    'ocsp-request',
    'pfx-bags',
    'self-signed-certificate',
    'timestamp-request',
]

describe('Examples', () => {
    for (const exampleFile of examples) {
        test.sequential(`${exampleFile}`, async () => {
            const logs: string[] = []
            const { log } = console
            console.log = (...args: any[]) => {
                log(...args)
                logs.push(args.map((a) => String(a)).join(' '))
            }

            /* @vite-ignore */
            await import(`../../examples/${exampleFile}.ts`)

            expect(logs).toMatchSnapshot()
            console.log = log
        })
    }
})
