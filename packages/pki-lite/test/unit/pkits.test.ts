/**
 * NIST Public Key Interoperability Test Suite (PKITS), sections 4.8 to 4.13: certificate
 * policies, requireExplicitPolicy, policy mappings, inhibitPolicyMapping, inhibitAnyPolicy
 * and name constraints. The certificates and paths come from NIST's own data
 * (test-fixtures/pkits, see its README); the verdicts below are transcribed from the
 * PKITS specification (PKITS.pdf, version 1.0.1).
 *
 * "Default settings" in PKITS: user-initial-policy-set = any-policy and the
 * initial-explicit-policy, initial-policy-mapping-inhibit and initial-inhibit-any-policy
 * indicators all clear. Revocation is not checked: these sections do not test it.
 */
import { describe, expect, test } from 'vitest'
import {
    pkitsCertificates,
    pkitsTests,
} from '../../test-fixtures/pkits/pkits.js'
import { CertificateValidator } from '../../src/core/CertificateValidator.js'
import { Certificate } from '../../src/x509/Certificate.js'

/** NIST-test-policy-n */
const P = (n: number) => `2.16.840.1.101.3.2.1.48.${n}`

type Settings = {
    initialPolicySet?: string[]
    initialExplicitPolicy?: boolean
    initialPolicyMappingInhibit?: boolean
    initialAnyPolicyInhibit?: boolean
}
type Run = Settings & { valid: boolean }

const explicit = { initialExplicitPolicy: true }
const policies = (...n: number[]) => ({ initialPolicySet: n.map(P) })

/**
 * The runs the specification lists for a test. Tests not listed here are run once with
 * the default settings, expecting what their title says ("Valid ..." / "Invalid ...").
 */
const RUNS: Record<string, Run[]> = {
    // 4.8 Certificate Policies (titles do not say valid/invalid)
    '4.8.1': [
        { ...explicit, valid: true },
        { ...explicit, ...policies(1), valid: true },
        { ...explicit, ...policies(2), valid: false },
        { ...explicit, ...policies(1, 2), valid: true },
    ],
    '4.8.2': [{ valid: true }, { ...explicit, valid: false }],
    '4.8.3': [
        { valid: true },
        { ...explicit, valid: false },
        { ...explicit, ...policies(1, 2), valid: false },
    ],
    '4.8.4': [{ valid: false }],
    '4.8.5': [{ valid: false }],
    '4.8.6': [
        { valid: true },
        { ...policies(1), valid: true },
        { ...policies(2), valid: false },
    ],
    '4.8.7': [{ valid: false }],
    '4.8.8': [{ valid: false }],
    '4.8.9': [{ valid: false }],
    '4.8.10': [
        { valid: true },
        { ...policies(1), valid: true },
        { ...policies(2), valid: true },
    ],
    '4.8.11': [{ valid: true }, { ...policies(1), valid: true }],
    '4.8.12': [{ valid: false }],
    '4.8.13': [
        { ...policies(1), valid: true },
        { ...policies(2), valid: true },
        { ...policies(3), valid: true },
    ],
    '4.8.14': [
        { ...policies(1), valid: true },
        { ...policies(2), valid: false },
    ],
    '4.8.15': [{ valid: true }],
    '4.8.16': [{ valid: true }],
    '4.8.17': [{ valid: true }],
    '4.8.18': [
        { ...policies(1), valid: true },
        { ...policies(2), valid: true },
    ],
    '4.8.19': [{ valid: true }],
    '4.8.20': [{ valid: true }, { ...explicit, valid: true }],
    // 4.10 Policy Mappings: extra inputs on top of the default run
    '4.10.1': [
        { valid: true },
        { ...policies(1), valid: true },
        { ...policies(2), valid: false },
        { initialPolicyMappingInhibit: true, valid: false },
    ],
    '4.10.2': [
        { valid: false },
        { initialPolicyMappingInhibit: true, valid: false },
    ],
    '4.10.3': [
        { valid: true },
        { ...policies(1), valid: false },
        { ...policies(2), valid: true },
    ],
    '4.10.5': [
        { valid: true },
        { ...policies(1), valid: true },
        { ...policies(6), valid: false },
    ],
    '4.10.6': [
        { valid: true },
        { ...policies(1), valid: true },
        { ...policies(6), valid: false },
    ],
    '4.10.12': [
        { valid: true },
        { ...policies(1), valid: true },
        { ...policies(2), valid: true },
    ],
    // 4.12 Inhibit Any Policy
    '4.12.3': [
        { valid: true },
        { initialAnyPolicyInhibit: true, valid: false },
    ],
}

function runsFor(id: string, title: string): Run[] {
    if (RUNS[id]) return RUNS[id]
    if (title.startsWith('Valid ')) return [{ valid: true }]
    if (title.startsWith('Invalid ')) return [{ valid: false }]
    throw new Error(`PKITS ${id} "${title}": no expected result`)
}

const certificate = (name: string) => {
    const base64 = pkitsCertificates[name]
    return Certificate.fromDer(
        Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)),
    )
}

const describeSettings = (settings: Settings) => {
    const parts = [
        settings.initialPolicySet &&
            `initial-policy-set {${settings.initialPolicySet
                .map((oid) => `NIST-test-policy-${oid.split('.').pop()}`)
                .join(', ')}}`,
        settings.initialExplicitPolicy && 'initial-explicit-policy',
        settings.initialPolicyMappingInhibit &&
            'initial-policy-mapping-inhibit',
        settings.initialAnyPolicyInhibit && 'initial-inhibit-any-policy',
    ].filter(Boolean)
    return parts.length ? parts.join(', ') : 'default settings'
}

describe('NIST PKITS 4.8 to 4.13', () => {
    test('covers every test in sections 4.8 to 4.13', () => {
        const count = (section: string) =>
            pkitsTests.filter((t) => t.id.startsWith(`${section}.`)).length
        // 4.8: 20, 4.9: 8, 4.10: 14, 4.11: 11, 4.12: 10, 4.13: 38
        expect(
            [4.8, 4.9, '4.10', 4.11, 4.12, 4.13].map(String).map(count),
        ).toEqual([20, 8, 14, 11, 10, 38])
        for (const id of Object.keys(RUNS)) {
            expect(
                pkitsTests.some((t) => t.id === id),
                id,
            ).toBe(true)
        }
    })

    for (const { id, title, path } of pkitsTests) {
        for (const run of runsFor(id, title)) {
            const { valid, ...settings } = run
            test(`${id} ${title} (${describeSettings(settings)}): ${valid ? 'valid' : 'invalid'}`, async () => {
                const [anchor, ...rest] = path.map(certificate)
                const leaf = rest.pop()!
                const result = await new CertificateValidator().validate(leaf, {
                    validateChain: true,
                    trustAnchors: [{ certificate: anchor }],
                    otherCertificates: rest,
                    ...settings,
                })
                expect(result.isValid, result.messages.join('; ')).toBe(valid)
            })
        }
    }
})
