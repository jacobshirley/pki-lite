import { beforeAll, describe, expect, test } from 'vitest'
import { CertificateValidator } from './CertificateValidator.js'
import { KeyGen } from './KeyGen.js'
import { ANY_POLICY } from './PolicyProcessor.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Certificate } from '../x509/Certificate.js'
import { Extension } from '../x509/Extension.js'
import { OIDs } from './OIDs.js'
import { CertificateBuilder } from './builders/CertificateBuilder.js'

type Keys = { privateKey: PrivateKeyInfo; publicKey: SubjectPublicKeyInfo }
const A = '1.2.3.4.1'
const B = '1.2.3.4.2'
const C = '1.2.3.4.3'

const ecdsa = {
    type: 'ECDSA' as const,
    params: { namedCurve: 'P-256' as const, hash: 'SHA-256' as const },
}

describe('RFC 5280 6.1 policy processing', () => {
    let rootKeys: Keys, caKeys: Keys, leafKeys: Keys
    const validator = new CertificateValidator()

    beforeAll(async () => {
        const pair = () => KeyGen.generateEcPair({ namedCurve: 'P-256' })
        ;[rootKeys, caKeys, leafKeys] = await Promise.all([
            pair(),
            pair(),
            pair(),
        ])
    })

    type Customise = (builder: CertificateBuilder) => void

    /** root -> CA -> leaf, each customised with extensions */
    async function chain(options: {
        root?: Customise
        ca?: Customise
        leaf?: Customise
    }) {
        const base = (subject: string, keys: Keys, isCa: boolean) =>
            Certificate.builder()
                .setSubject(subject)
                .setPublicKey(keys.publicKey)
                .setAlgorithm(ecdsa)
                .setValidityDays(30)
                .generateSerialNumber()
                .addBasicConstraints(isCa)
        const rootBuilder = base('CN=Root', rootKeys, true)
        options.root?.(rootBuilder)
        const root = await rootBuilder
            .setPrivateKey(rootKeys.privateKey)
            .selfSign()

        const caBuilder = base('CN=CA', caKeys, true)
        options.ca?.(caBuilder)
        const ca = await caBuilder
            .setIssuer(root)
            .setIssuerPrivateKey(rootKeys.privateKey)
            .sign()

        const leafBuilder = base('CN=Leaf', leafKeys, false)
        options.leaf?.(leafBuilder)
        const leaf = await leafBuilder
            .setIssuer(ca)
            .setIssuerPrivateKey(caKeys.privateKey)
            .sign()
        return { root, ca, leaf }
    }

    const validate = async (
        chained: { root: Certificate; ca: Certificate; leaf: Certificate },
        extra: object = {},
    ) =>
        validator.validate(chained.leaf, {
            validateChain: true,
            trustAnchors: [{ certificate: chained.root }],
            otherCertificates: [chained.ca],
            ...extra,
        })

    test('a path without policies is fine unless a policy is required', async () => {
        const c = await chain({})
        const result = await validate(c)
        expect(result.isValid, result.messages.join('; ')).toBe(true)

        const required = await validate(c, { initialExplicitPolicy: true })
        expect(required.isValid).toBe(false)
        expect(required.messages.join(' ')).toContain('no acceptable policy')
    })

    test('a policy shared by the whole path is valid', async () => {
        const c = await chain({
            ca: (b) => b.addCertificatePolicies(A),
            leaf: (b) => b.addCertificatePolicies(A, B),
        })
        const result = await validate(c, { requiredPolicies: [A] })
        expect(result.isValid, result.messages.join('; ')).toBe(true)
        expect(result.policyResult?.validPolicies).toEqual([A])

        const other = await validate(c, { requiredPolicies: [B] })
        expect(other.isValid).toBe(false)
        expect(other.policyResult?.violations).toContain(
            `Required policy not found: ${B}`,
        )
    })

    test('disjoint policies leave nothing valid', async () => {
        const c = await chain({
            ca: (b) => b.addCertificatePolicies(A),
            leaf: (b) => b.addCertificatePolicies(B),
        })
        expect((await validate(c)).isValid).toBe(true) // nothing demands a policy
        expect(
            (await validate(c, { initialExplicitPolicy: true })).isValid,
        ).toBe(false)
    })

    test('anyPolicy in the CA lets the leaf policies through', async () => {
        const c = await chain({
            ca: (b) => b.addCertificatePolicies(ANY_POLICY),
            leaf: (b) => b.addCertificatePolicies(B),
        })
        const result = await validate(c, { requiredPolicies: [B] })
        expect(result.isValid, result.messages.join('; ')).toBe(true)
        expect(result.policyResult?.validPolicies).toEqual([B])
    })

    test('anyPolicy in the leaf takes the CA policies', async () => {
        const c = await chain({
            ca: (b) => b.addCertificatePolicies(A),
            leaf: (b) => b.addCertificatePolicies(ANY_POLICY),
        })
        const result = await validate(c, { requiredPolicies: [A] })
        expect(result.isValid, result.messages.join('; ')).toBe(true)
        expect(result.policyResult?.validPolicies).toEqual([A])
    })

    test('inhibitAnyPolicy stops anyPolicy from matching', async () => {
        const c = await chain({
            root: (b) => b.addInhibitAnyPolicy(0),
            ca: (b) => b.addCertificatePolicies(A),
            leaf: (b) => b.addCertificatePolicies(ANY_POLICY),
        })
        // the root's extension is not part of the path (the trust anchor), so use the CA's
        expect((await validate(c, { requiredPolicies: [A] })).isValid).toBe(
            true,
        )

        const inhibited = await chain({
            ca: (b) => b.addCertificatePolicies(A).addInhibitAnyPolicy(0),
            leaf: (b) => b.addCertificatePolicies(ANY_POLICY),
        })
        expect(
            (await validate(inhibited, { initialExplicitPolicy: true }))
                .isValid,
        ).toBe(false)
        expect(
            (await validate(inhibited, { initialAnyPolicyInhibit: false }))
                .isValid,
        ).toBe(true)
    })

    test('initialAnyPolicyInhibit ignores anyPolicy certificates', async () => {
        const c = await chain({
            ca: (b) => b.addCertificatePolicies(A),
            leaf: (b) => b.addCertificatePolicies(ANY_POLICY),
        })
        const result = await validate(c, {
            initialAnyPolicyInhibit: true,
            initialExplicitPolicy: true,
        })
        expect(result.isValid).toBe(false)
    })

    test('policy mappings translate the CA policy for the leaf', async () => {
        const c = await chain({
            ca: (b) =>
                b.addCertificatePolicies(A).addPolicyMappings({
                    issuerDomainPolicy: A,
                    subjectDomainPolicy: B,
                }),
            leaf: (b) => b.addCertificatePolicies(B),
        })
        const result = await validate(c, { requiredPolicies: [B] })
        expect(result.isValid, result.messages.join('; ')).toBe(true)
        // the user-initial-policy-set speaks the trust anchor's policy domain: A, not B
        const strict = { initialExplicitPolicy: true }
        expect(
            (await validate(c, { ...strict, initialPolicySet: [A] })).isValid,
        ).toBe(true)
        expect(
            (await validate(c, { ...strict, initialPolicySet: [B] })).isValid,
        ).toBe(false)
    })

    test('inhibitPolicyMapping and initialPolicyMappingInhibit stop mappings', async () => {
        const mapped = (inhibit: Customise = () => {}) =>
            chain({
                ca: (b) => {
                    b.addCertificatePolicies(A).addPolicyMappings({
                        issuerDomainPolicy: A,
                        subjectDomainPolicy: B,
                    })
                    inhibit(b)
                },
                leaf: (b) => b.addCertificatePolicies(B),
            })

        const c = await mapped()
        const refused = await validate(c, {
            initialPolicyMappingInhibit: true,
            initialExplicitPolicy: true,
        })
        expect(refused.isValid).toBe(false)

        // a CA's inhibitPolicyMapping applies to the certificates after it, not to its
        // own mappings (6.1.4 (b) runs before (i))
        const own = await mapped((b) =>
            b.addPolicyConstraints({ inhibitPolicyMapping: 0 }),
        )
        expect(
            (await validate(own, { initialExplicitPolicy: true })).isValid,
        ).toBe(true)
    })

    test('policy constraints require an explicit policy', async () => {
        const c = await chain({
            ca: (b) => b.addPolicyConstraints({ requireExplicitPolicy: 0 }),
            // the leaf has no policies
        })
        const result = await validate(c)
        expect(result.isValid).toBe(false)
        expect(result.messages.join(' ')).toContain('no acceptable policy')

        const ok = await chain({
            ca: (b) =>
                b
                    .addCertificatePolicies(A)
                    .addPolicyConstraints({ requireExplicitPolicy: 0 }),
            leaf: (b) => b.addCertificatePolicies(A),
        })
        expect((await validate(ok)).isValid).toBe(true)
    })

    test('the user-initial-policy-set restricts the result', async () => {
        const c = await chain({
            ca: (b) => b.addCertificatePolicies(A, B),
            leaf: (b) => b.addCertificatePolicies(A, B),
        })
        const onlyB = await validate(c, { initialPolicySet: [B] })
        expect(onlyB.isValid, onlyB.messages.join('; ')).toBe(true)
        expect(onlyB.policyResult?.validPolicies).toEqual([B])

        const noMatch = await validate(c, {
            initialPolicySet: [C],
            initialExplicitPolicy: true,
        })
        expect(noMatch.isValid).toBe(false)
    })

    test('unreadable policy extensions fail closed', async () => {
        const c = await chain({
            ca: (b) =>
                b.addExtension(
                    new Extension({
                        extnID: OIDs.EXTENSION.CERTIFICATE_POLICIES,
                        critical: false,
                        extnValue: new Uint8Array([0x04, 0x01, 0x00]) as never,
                    }),
                ),
        })
        const result = await validate(c)
        expect(result.isValid).toBe(false)
        expect(result.messages.join(' ')).toContain(
            'cannot read the certificate policies',
        )
    })

    test('policy processing can be switched off', async () => {
        const c = await chain({
            ca: (b) => b.addPolicyConstraints({ requireExplicitPolicy: 0 }),
        })
        expect((await validate(c)).isValid).toBe(false)
        expect((await validate(c, { validatePolicies: false })).isValid).toBe(
            true,
        )
    })
})
