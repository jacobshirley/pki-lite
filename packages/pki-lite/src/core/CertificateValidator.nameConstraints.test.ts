import { beforeAll, describe, expect, test } from 'vitest'
import { CertificateValidator } from './CertificateValidator.js'
import { KeyGen } from './KeyGen.js'
import { OIDs } from './OIDs.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Certificate } from '../x509/Certificate.js'
import { Extension } from '../x509/Extension.js'
import {
    GeneralSubtree,
    NameConstraints,
} from '../x509/extensions/NameConstraints.js'
import { dNSName, directoryName, GeneralName } from '../x509/GeneralName.js'
import { Name } from '../x509/Name.js'

/**
 * Name constraints on the CAs of a real (signed) chain must constrain the certificates
 * below them: RFC 5280 6.1.3 (b)/(c), 6.1.4 (g).
 */
describe('CertificateValidator: name constraints from CA certificates', () => {
    type Keys = { privateKey: PrivateKeyInfo; publicKey: SubjectPublicKeyInfo }
    let rootKeys: Keys, intermediateKeys: Keys, leafKeys: Keys
    const validator = new CertificateValidator()

    beforeAll(async () => {
        const pair = () => KeyGen.generateEcPair({ namedCurve: 'P-256' })
        ;[rootKeys, intermediateKeys, leafKeys] = await Promise.all([
            pair(),
            pair(),
            pair(),
        ])
    })

    const ecdsa = {
        type: 'ECDSA' as const,
        params: { namedCurve: 'P-256' as const, hash: 'SHA-256' as const },
    }
    const dns = (value: string) => new dNSName({ value })
    const permit = (...bases: GeneralName[]) =>
        new NameConstraints({
            permittedSubtrees: bases.map(
                (base) => new GeneralSubtree({ base }),
            ),
        })
    const exclude = (...bases: GeneralName[]) =>
        new NameConstraints({
            excludedSubtrees: bases.map((base) => new GeneralSubtree({ base })),
        })
    const nameConstraintsExtension = (value: NameConstraints | Uint8Array) =>
        new Extension({
            extnID: OIDs.EXTENSION.NAME_CONSTRAINTS,
            critical: true,
            extnValue: value as NameConstraints,
        })

    /** A CA certificate, optionally constrained, issued by `issuer` (self-signed if none) */
    async function ca(options: {
        subject: string
        keys: Keys
        constraints?: NameConstraints | Uint8Array
        issuer?: { certificate: Certificate; keys: Keys }
        names?: string[]
        /** key identifiers: this certificate's own, and its issuer's */
        ski?: Uint8Array<ArrayBuffer>
        aki?: Uint8Array<ArrayBuffer>
    }) {
        const builder = Certificate.builder()
            .setSubject(options.subject)
            .setPublicKey(options.keys.publicKey)
            .setAlgorithm(ecdsa)
            .setValidityDays(30)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .addKeyUsage({ keyCertSign: true, cRLSign: true })
        if (options.names) builder.addSubjectAltName(...options.names)
        if (options.ski) builder.addSubjectKeyIdentifier(options.ski)
        if (options.aki) builder.addAuthorityKeyIdentifier(options.aki)
        if (options.constraints) {
            builder.addExtension(nameConstraintsExtension(options.constraints))
        }
        if (!options.issuer) {
            return builder.setPrivateKey(options.keys.privateKey).selfSign()
        }
        return builder
            .setIssuer(options.issuer.certificate)
            .setIssuerPrivateKey(options.issuer.keys.privateKey)
            .sign()
    }

    async function leaf(
        issuer: { certificate: Certificate; keys: Keys },
        names: string[],
        subject = 'CN=Server',
        aki?: Uint8Array<ArrayBuffer>,
    ) {
        const builder = Certificate.builder()
            .setSubject(subject)
            .setIssuer(issuer.certificate)
            .setPublicKey(leafKeys.publicKey)
            .setIssuerPrivateKey(issuer.keys.privateKey)
            .setAlgorithm(ecdsa)
            .setValidityDays(30)
            .generateSerialNumber()
            .addBasicConstraints(false)
            .addSubjectAltName(...names)
        if (aki) builder.addAuthorityKeyIdentifier(aki)
        return builder.sign()
    }

    const validate = (
        certificate: Certificate,
        root: Certificate,
        others: Certificate[] = [],
        extra: object = {},
    ) =>
        validator.validate(certificate, {
            validateChain: true,
            validateNameConstraints: true,
            trustAnchors: [{ certificate: root }],
            otherCertificates: others,
            ...extra,
        })

    test('constraints in the root certificate apply to the leaf', async () => {
        const root = await ca({
            subject: 'CN=Constrained Root',
            keys: rootKeys,
            constraints: permit(dns('example.com')),
        })
        const issuer = { certificate: root, keys: rootKeys }

        const allowed = await validate(
            await leaf(issuer, ['www.example.com']),
            root,
        )
        expect(allowed.isValid, allowed.messages.join('; ')).toBe(true)

        const denied = await validate(
            await leaf(issuer, ['www.evil.org']),
            root,
        )
        expect(denied.isValid).toBe(false)
        expect(denied.messages.join(' ')).toContain(
            'Name constraints violation',
        )
        expect(denied.messages.join(' ')).toContain('www.evil.org')
        expect(denied.messages.join(' ')).toContain('Constrained Root')
    })

    test('excluded subtrees in the root certificate', async () => {
        const root = await ca({
            subject: 'CN=Root',
            keys: rootKeys,
            constraints: exclude(dns('secret.example.com')),
        })
        const issuer = { certificate: root, keys: rootKeys }

        expect(
            (await validate(await leaf(issuer, ['www.example.com']), root))
                .isValid,
        ).toBe(true)
        expect(
            (
                await validate(
                    await leaf(issuer, [
                        'www.example.com',
                        'a.secret.example.com',
                    ]),
                    root,
                )
            ).isValid,
        ).toBe(false)
    })

    test("an intermediate's constraints apply to the leaf below it", async () => {
        const root = await ca({ subject: 'CN=Root', keys: rootKeys })
        const intermediate = await ca({
            subject: 'CN=Constrained Intermediate',
            keys: intermediateKeys,
            constraints: permit(dns('example.com')),
            issuer: { certificate: root, keys: rootKeys },
        })
        const issuer = { certificate: intermediate, keys: intermediateKeys }

        const allowed = await validate(
            await leaf(issuer, ['www.example.com']),
            root,
            [intermediate],
        )
        expect(allowed.isValid, allowed.messages.join('; ')).toBe(true)

        const denied = await validate(
            await leaf(issuer, ['www.evil.org']),
            root,
            [intermediate],
        )
        expect(denied.isValid).toBe(false)
        expect(denied.messages.join(' ')).toContain('Constrained Intermediate')
    })

    test("the root's constraints also apply to intermediate CAs", async () => {
        const root = await ca({
            subject: 'CN=Root',
            keys: rootKeys,
            constraints: permit(
                directoryName.fromName(Name.parse('O=Example Org')),
            ),
        })
        const rootIssuer = { certificate: root, keys: rootKeys }

        const inside = await ca({
            subject: 'O=Example Org, CN=Sub CA',
            keys: intermediateKeys,
            issuer: rootIssuer,
        })
        const ok = await validate(
            await leaf(
                { certificate: inside, keys: intermediateKeys },
                [],
                'O=Example Org, CN=Server',
            ),
            root,
            [inside],
        )
        expect(ok.isValid, ok.messages.join('; ')).toBe(true)

        const outside = await ca({
            subject: 'O=Somebody Else, CN=Sub CA',
            keys: intermediateKeys,
            issuer: rootIssuer,
        })
        const bad = await validate(
            await leaf(
                { certificate: outside, keys: intermediateKeys },
                [],
                'O=Example Org, CN=Server',
            ),
            root,
            [outside],
        )
        expect(bad.isValid).toBe(false)
        expect(bad.messages.join(' ')).toContain('directoryName')
    })

    test('a self-issued intermediate is exempt, but the leaf is not', async () => {
        // two CAs with the same name: key identifiers say which one issued the leaf
        const rootId = new Uint8Array([1, 1, 1, 1])
        const rolloverId = new Uint8Array([2, 2, 2, 2])
        const root = await ca({
            subject: 'CN=Root',
            keys: rootKeys,
            constraints: permit(dns('example.com')),
            ski: rootId,
        })
        // same subject and issuer (a CA key rollover), with a name outside the constraints
        const selfIssued = await ca({
            subject: 'CN=Root',
            keys: intermediateKeys,
            issuer: { certificate: root, keys: rootKeys },
            names: ['rollover.evil.org'],
            ski: rolloverId,
            aki: rootId,
        })
        const issuer = { certificate: selfIssued, keys: intermediateKeys }

        const allowed = await validate(
            await leaf(issuer, ['www.example.com'], 'CN=Server', rolloverId),
            root,
            [selfIssued],
        )
        expect(allowed.isValid, allowed.messages.join('; ')).toBe(true)

        const denied = await validate(
            await leaf(issuer, ['www.evil.org'], 'CN=Server', rolloverId),
            root,
            [selfIssued],
        )
        expect(denied.isValid).toBe(false)
    })

    test('constraints given with the trust anchor are applied as well', async () => {
        const root = await ca({
            subject: 'CN=Root',
            keys: rootKeys,
            constraints: permit(dns('example.com')),
        })
        const issuer = { certificate: root, keys: rootKeys }
        const certificate = await leaf(issuer, ['www.example.com'])

        // allowed by the CA's own constraints, refused by the extra ones
        const result = await validator.validate(certificate, {
            validateChain: true,
            validateNameConstraints: true,
            trustAnchors: [
                {
                    certificate: root,
                    nameConstraints: exclude(dns('www.example.com')),
                },
            ],
        })
        expect(result.isValid).toBe(false)
        expect(result.messages.join(' ')).toContain('trust anchor')
    })

    test('constraints are only enforced when validateNameConstraints is set', async () => {
        const root = await ca({
            subject: 'CN=Root',
            keys: rootKeys,
            constraints: permit(dns('example.com')),
        })
        const certificate = await leaf({ certificate: root, keys: rootKeys }, [
            'www.evil.org',
        ])

        const off = await validate(certificate, root, [], {
            validateNameConstraints: false,
        })
        expect(off.isValid, off.messages.join('; ')).toBe(true)
        expect((await validate(certificate, root)).isValid).toBe(false)
    })

    test('unreadable name constraints fail closed', async () => {
        const root = await ca({
            subject: 'CN=Broken Constraints Root',
            keys: rootKeys,
            constraints: new Uint8Array([0x04, 0x01, 0x00]), // not a NameConstraints
        })
        const certificate = await leaf({ certificate: root, keys: rootKeys }, [
            'www.example.com',
        ])
        const result = await validate(certificate, root)
        expect(result.isValid).toBe(false)
        expect(result.messages.join(' ')).toContain(
            'cannot read the name constraints',
        )
    })
})
