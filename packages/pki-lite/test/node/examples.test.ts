/**
 * Runs the repository's examples (../../examples) and fails if one throws or writes to
 * stderr, so they cannot silently stop working as the API changes.
 *
 * Only the self-contained, offline examples are run. The others need something you have
 * to supply: 001 and 002 (and 004/005/007) contain `{your ... here}` placeholders and
 * make network requests (CRL/OCSP/timestamp servers).
 *
 * The examples import `pki-lite/...`, which resolves to the compiled `dist`, so run
 * `pnpm compile` first (CI does).
 */
import { describe, expect, test } from 'vitest'

const examples = [
    '003-timestamp-request',
    '006-extended-crypto',
    '008-enveloped-data',
    '009-key-generation',
    '010-certificate-signing-request',
    '011-ca-certificate-issuance',
    '012-certificate-validation',
    '013-certificate-builder',
    '014-pfx-builder',
    '015-encrypted-data-builder',
    '016-crl-builder',
    '017-ocsp-response-builder',
    '018-auth-enveloped-data',
    '019-encrypted-private-key',
    '020-certificate-extensions',
    '021-name-constraints',
    '022-signed-data-verification',
    '023-signature-algorithms',
    '024-asn1-and-pem',
    '025-reading-openssl-output',
    '026-openssl-defaults-with-extended-crypto',
    '027-certificate-policies',
]

/** Silences console output while an example runs, keeping what went to stderr. */
function captureConsole() {
    const original = { ...console }
    const stderr: string[] = []
    const quiet = () => {}
    console.log = quiet
    console.info = quiet
    console.debug = quiet
    console.warn = (...args: unknown[]) => void stderr.push(args.join(' '))
    console.error = (...args: unknown[]) => void stderr.push(args.join(' '))
    return {
        stderr,
        restore: () => Object.assign(console, original),
    }
}

describe('examples', { timeout: 120_000 }, () => {
    for (const example of examples) {
        test(example, async () => {
            const output = captureConsole()
            try {
                await import(`../../../../examples/${example}.ts`)
            } finally {
                output.restore()
            }
            expect(output.stderr).toEqual([])
        })
    }
})
