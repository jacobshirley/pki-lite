/**
 * NIST Public Key Interoperability Test Suite (PKITS), every test in section 4:
 * signatures, validity periods, name chaining, revocation, self-issued certificates, basic
 * constraints, key usage, certificate policies (4.8 to 4.12), name constraints,
 * distribution points, delta-CRLs and private extensions. The certificates, CRLs and
 * paths come from NIST's own data (test-fixtures/pkits, see its README); the verdicts
 * below are transcribed from the PKITS specification (PKITS.pdf, version 1.0.1).
 *
 * "Default settings" in PKITS: user-initial-policy-set = any-policy and the
 * initial-explicit-policy, initial-policy-mapping-inhibit and initial-inhibit-any-policy
 * indicators all clear. Every test is run with signature checking, CA constraint
 * enforcement and CRL checking on (all opt-in in pki-lite), and the CRLs the
 * specification lists for it.
 */
import { describe, expect, test } from 'vitest'
import { pkitsFiles, pkitsTests } from '../../test-fixtures/pkits/pkits.js'
import { CertificateValidator } from '../../src/core/CertificateValidator.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { CertificateList } from '../../src/x509/CertificateList.js'

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
    // 4.4 Basic Certificate Revocation: no CRL from the intermediate CA, so the end
    // certificate's status cannot be determined
    '4.4.1': [{ valid: false }],
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

const der = (name: string) =>
    Uint8Array.from(atob(pkitsFiles[name]), (c) => c.charCodeAt(0))
const isCrl = (name: string) => name.endsWith('CRL')

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

/**
 * Tests pki-lite does not pass yet, each with the reason. They run with `test.fails`, so
 * fixing one makes its test fail with "expected to fail": delete the entry then.
 */
const DSA =
    'WebCrypto has no DSA, so these DSA-signed paths cannot be verified (they fail closed). Not planned for the core package.'
const REENCODE =
    "The signature check re-encodes the TBSCertificate instead of using the signed bytes: this end certificate's GeneralizedTime notBefore (before 2050) is re-encoded as UTCTime, so a valid signature fails."
const NAMES =
    'Name chaining compares distinguished names exactly; RFC 5280 7.1 requires the comparison to ignore case and extra whitespace and to treat PrintableString and UTF8String values alike.'
const CRL =
    "CRL checking does not follow RFC 5280 6.3: it looks for the serial number in every CRL regardless of issuer, does not verify the CRL's signature, issuer or dates, does not require a CRL for each certificate, and the serial comparison is case-sensitive hex."
const DP =
    'CRL distribution points, issuingDistributionPoint scopes, indirect CRLs and cRLIssuer are not supported.'
const DELTA = 'Delta CRLs are not supported.'
const CRITICAL =
    'Unrecognised critical certificate extensions are not rejected (RFC 5280 4.2, 6.1.3).'
const KNOWN_ISSUES: Record<string, string> = {
    '4.1.4': DSA,
    '4.1.5': DSA,
    '4.2.4': REENCODE,
    '4.3.3': NAMES,
    '4.3.4': NAMES,
    '4.3.5': NAMES,
    '4.3.10': NAMES,
    '4.3.11': NAMES,
    '4.4.1': CRL,
    '4.4.4': CRL,
    '4.4.5': CRL,
    '4.4.6': CRL,
    '4.4.7': CRL,
    '4.4.10': CRL,
    '4.4.11': CRL,
    '4.4.12': CRL,
    '4.4.21': CRL,
    '4.7.4': CRL,
    '4.7.5': CRL,
    '4.14.3': DP,
    '4.14.8': DP,
    '4.14.9': DP,
    '4.14.11': DP,
    '4.14.12': DP,
    '4.14.14': DP,
    '4.14.17': DP,
    '4.14.25': DP,
    '4.14.26': DP,
    '4.14.27': DP,
    '4.14.33': DP,
    '4.14.35': DP,
    '4.15.1': DELTA,
    '4.15.5': DELTA,
    '4.15.7': DELTA,
    '4.15.10': DELTA,
    '4.16.2': CRITICAL,
}

const SECTION_COUNTS: Record<string, number> = {
    '4.1': 6,
    '4.2': 8,
    '4.3': 11,
    '4.4': 21,
    '4.5': 8,
    '4.6': 17,
    '4.7': 5,
    '4.8': 20,
    '4.9': 8,
    '4.10': 14,
    '4.11': 11,
    '4.12': 10,
    '4.13': 38,
    '4.14': 35,
    '4.15': 10,
    '4.16': 2,
}

describe('NIST PKITS section 4', () => {
    test('covers every test in section 4', () => {
        const counts: Record<string, number> = {}
        for (const { id } of pkitsTests) {
            const section = id.split('.').slice(0, 2).join('.')
            counts[section] = (counts[section] ?? 0) + 1
        }
        expect(counts).toEqual(SECTION_COUNTS)
        for (const id of [...Object.keys(RUNS), ...Object.keys(KNOWN_ISSUES)]) {
            const known = id.split(' ')[0]
            expect(
                pkitsTests.some((t) => t.id === known),
                id,
            ).toBe(true)
        }
    })

    for (const { id, title, path } of pkitsTests) {
        for (const run of runsFor(id, title)) {
            const { valid, ...settings } = run
            const label = describeSettings(settings)
            const name = `${id} ${title} (${label}): ${valid ? 'valid' : 'invalid'}`
            const issue = KNOWN_ISSUES[id] ?? KNOWN_ISSUES[`${id} (${label})`]
            ;(issue ? test.fails : test)(name, async () => {
                const certificates = path.filter((n) => !isCrl(n))
                const anchor = Certificate.fromDer(der(certificates[0]))
                const leaf = Certificate.fromDer(der(certificates.at(-1)!))
                const result = await new CertificateValidator().validate(
                    leaf,
                    {
                        validateChain: true,
                        trustAnchors: [{ certificate: anchor }],
                        otherCertificates: certificates
                            .slice(1, -1)
                            .map((n) => Certificate.fromDer(der(n))),
                        // both are opt-in; a relying party that follows RFC 5280 6.1 needs them
                        checkSignature: true,
                        enforceCAConstraints: true,
                        checkCRL: true,
                        ...settings,
                    },
                    {
                        crls: path
                            .filter(isCrl)
                            .map((n) => CertificateList.fromDer(der(n))),
                    },
                )
                expect(result.isValid, result.messages.join('; ')).toBe(valid)
            })
        }
    }
})
