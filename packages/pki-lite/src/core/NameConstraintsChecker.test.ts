import { beforeAll, describe, expect, test } from 'vitest'
import { KeyGen } from './KeyGen.js'
import { Certificate } from '../x509/Certificate.js'
import {
    dNSName,
    directoryName,
    iPAddress,
    otherName,
    rfc822Name,
    uniformResourceIdentifier,
    GeneralName,
} from '../x509/GeneralName.js'
import { Name } from '../x509/Name.js'
import {
    GeneralSubtree,
    NameConstraints,
} from '../x509/extensions/NameConstraints.js'
import {
    MAX_COMPARISONS,
    checkNameConstraints,
    dnsWithin,
    dnWithin,
    emailWithin,
    ipWithin,
    normalizeHost,
    uriHost,
    uriWithin,
} from './NameConstraintsChecker.js'
import { asn1js } from './PkiBase.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'

describe('matching rules (RFC 5280 4.2.1.10)', () => {
    test('dNSName: the constraint itself or any name below it', () => {
        expect(dnsWithin('example.com', 'example.com')).toBe(true)
        expect(dnsWithin('www.example.com', 'example.com')).toBe(true)
        expect(dnsWithin('a.b.example.com', 'example.com')).toBe(true)
        // a different domain that merely ends in the same letters
        expect(dnsWithin('badexample.com', 'example.com')).toBe(false)
        expect(dnsWithin('example.com.evil.org', 'example.com')).toBe(false)
        // case and a trailing dot do not matter
        expect(dnsWithin('WWW.Example.COM.', 'example.com')).toBe(true)
    })

    test('internationalised names compare in A-label form (RFC 5280 7.2)', () => {
        expect(normalizeHost('Bücher.Example')).toBe('xn--bcher-kva.example')
        expect(normalizeHost('*.bücher.example')).toBe(
            '*.xn--bcher-kva.example',
        )
        expect(normalizeHost('.bücher.example')).toBe('.xn--bcher-kva.example')
        expect(normalizeHost('XN--BCHER-KVA.example.')).toBe(
            'xn--bcher-kva.example',
        )

        // U-label and A-label spellings of the same domain match either way round
        expect(dnsWithin('www.xn--bcher-kva.example', 'bücher.example')).toBe(
            true,
        )
        expect(dnsWithin('www.bücher.example', 'xn--bcher-kva.example')).toBe(
            true,
        )
        expect(dnsWithin('www.bucher.example', 'bücher.example')).toBe(false)
        expect(emailWithin('a@xn--bcher-kva.example', 'bücher.example')).toBe(
            true,
        )
        expect(
            uriWithin('https://bücher.example/x', 'xn--bcher-kva.example'),
        ).toBe(true)
    })

    test('dNSName: a leading dot matches subdomains only', () => {
        expect(dnsWithin('www.example.com', '.example.com')).toBe(true)
        expect(dnsWithin('example.com', '.example.com')).toBe(false)
    })

    test('rfc822Name: mailbox, host and .domain forms', () => {
        // a full mailbox matches that mailbox only
        expect(emailWithin('a@example.com', 'a@example.com')).toBe(true)
        expect(emailWithin('b@example.com', 'a@example.com')).toBe(false)
        // a host matches mailboxes on exactly that host (host is case-insensitive)
        expect(emailWithin('anyone@Example.COM', 'example.com')).toBe(true)
        expect(emailWithin('anyone@mail.example.com', 'example.com')).toBe(
            false,
        )
        // a leading dot matches any subdomain host, not the domain itself
        expect(emailWithin('anyone@mail.example.com', '.example.com')).toBe(
            true,
        )
        expect(emailWithin('anyone@example.com', '.example.com')).toBe(false)
        // the local part is case-sensitive
        expect(emailWithin('A@example.com', 'a@example.com')).toBe(false)
        expect(emailWithin('no-at-sign', 'example.com')).toBe(false)
    })

    test('URI: the constraint applies to the host', () => {
        expect(uriHost('https://user:pw@Host.Example.com:8443/path?q#f')).toBe(
            'host.example.com',
        )
        // IP literals and URIs without an authority have no DNS host
        expect(uriHost('https://192.0.2.1/')).toBeUndefined()
        expect(uriHost('https://[2001:db8::1]/')).toBeUndefined()
        expect(uriHost('mailto:a@example.com')).toBeUndefined()

        expect(uriWithin('https://www.example.com/x', 'www.example.com')).toBe(
            true,
        )
        // a plain host constraint is that host only ...
        expect(uriWithin('https://a.www.example.com/', 'www.example.com')).toBe(
            false,
        )
        // ... a leading dot is any subdomain
        expect(uriWithin('https://a.example.com/', '.example.com')).toBe(true)
        expect(uriWithin('https://example.com/', '.example.com')).toBe(false)
        expect(uriWithin('https://192.0.2.1/', 'example.com')).toBe(false)
    })

    test('iPAddress: address and mask, same family only', () => {
        const net = (a: number[], mask: number[]) =>
            new Uint8Array([...a, ...mask])
        const slash24 = net([192, 0, 2, 0], [255, 255, 255, 0])

        expect(ipWithin(new Uint8Array([192, 0, 2, 77]), slash24)).toBe(true)
        expect(ipWithin(new Uint8Array([192, 0, 3, 1]), slash24)).toBe(false)
        // an IPv6 address never matches an IPv4 constraint (or the reverse)
        expect(ipWithin(new Uint8Array(16), slash24)).toBe(false)

        const v6 = new Uint8Array(32)
        v6.set([0x20, 0x01, 0x0d, 0xb8], 0)
        v6.set([0xff, 0xff, 0xff, 0xff], 16)
        const inside = new Uint8Array(16)
        inside.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        const outside = new Uint8Array(16)
        outside.set([0x20, 0x01, 0x0d, 0xb9])
        expect(ipWithin(inside, v6)).toBe(true)
        expect(ipWithin(outside, v6)).toBe(false)
    })

    test('directoryName: the constraint must be a prefix of the name', () => {
        const dn = (text: string) => Name.parse(text)
        expect(
            dnWithin(dn('O=Example Org, CN=Alice'), dn('O=Example Org')),
        ).toBe(true)
        expect(
            dnWithin(
                dn('C=GB, O=Example Org, CN=Alice'),
                dn('C=GB, O=Example Org'),
            ),
        ).toBe(true)
        // case and extra spaces are normalised
        expect(dnWithin(dn('O=Example  Org'), dn('O=example org'))).toBe(true)
        // not a prefix: the O is not first
        expect(
            dnWithin(dn('CN=Alice, O=Example Org'), dn('O=Example Org')),
        ).toBe(false)
        expect(dnWithin(dn('O=Other'), dn('O=Example Org'))).toBe(false)
        // a longer constraint than the name
        expect(
            dnWithin(dn('O=Example Org'), dn('O=Example Org, CN=Alice')),
        ).toBe(false)
    })
})

describe('checkNameConstraints', () => {
    let keys: Awaited<ReturnType<typeof KeyGen.generateEcPair>>

    beforeAll(async () => {
        keys = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
    })

    /** A self-signed certificate with the given subject and subjectAltName entries */
    async function certificate(options: {
        subject?: string
        names?: (string | GeneralName)[]
    }) {
        const builder = Certificate.builder()
            .setSubject(options.subject ?? 'CN=Some Server')
            .setPublicKey(keys.publicKey)
            .setPrivateKey(keys.privateKey)
            .setAlgorithm({
                type: 'ECDSA',
                params: { namedCurve: 'P-256', hash: 'SHA-256' },
            })
            .setValidityDays(1)
            .generateSerialNumber()
        if (options.names?.length) builder.addSubjectAltName(...options.names)
        return builder.selfSign()
    }

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
    const dns = (value: string) => new dNSName({ value })

    test('every name of a constrained kind must be permitted', async () => {
        const constraints = permit(dns('example.com'))

        expect(
            checkNameConstraints(
                await certificate({
                    names: ['a.example.com', 'b.example.com'],
                }),
                constraints,
            ),
        ).toBeUndefined()

        // one good name does not excuse a bad one
        const violation = checkNameConstraints(
            await certificate({ names: ['a.example.com', 'evil.org'] }),
            constraints,
        )
        expect(violation?.name).toBe('evil.org')
        expect(violation?.type).toBe('dNSName')
        expect(violation?.message).toContain('not within any permitted subtree')
    })

    test('kinds the constraints do not mention are unrestricted', async () => {
        const constraints = permit(dns('example.com'))
        const cert = await certificate({
            names: [
                'a.example.com',
                new rfc822Name({ value: 'anyone@anywhere.org' }),
                new iPAddress({ bytes: new Uint8Array([8, 8, 8, 8]) }),
            ],
        })
        expect(checkNameConstraints(cert, constraints)).toBeUndefined()
    })

    test('excluded subtrees reject names inside them', async () => {
        const constraints = exclude(dns('secret.example.com'))
        expect(
            checkNameConstraints(
                await certificate({ names: ['www.example.com'] }),
                constraints,
            ),
        ).toBeUndefined()
        expect(
            checkNameConstraints(
                await certificate({ names: ['x.secret.example.com'] }),
                constraints,
            )?.message,
        ).toContain('excluded subtree')
    })

    test('exclusion wins over permission', async () => {
        const constraints = new NameConstraints({
            permittedSubtrees: [
                new GeneralSubtree({ base: dns('example.com') }),
            ],
            excludedSubtrees: [
                new GeneralSubtree({ base: dns('secret.example.com') }),
            ],
        })
        expect(
            checkNameConstraints(
                await certificate({ names: ['secret.example.com'] }),
                constraints,
            )?.message,
        ).toContain('excluded')
    })

    test('wildcards: inside only if everything they match is inside', async () => {
        const wildcard = await certificate({ names: ['*.example.com'] })
        expect(
            checkNameConstraints(wildcard, permit(dns('example.com'))),
        ).toBeUndefined()
        // *.example.com can match hosts outside sub.example.com
        expect(
            checkNameConstraints(wildcard, permit(dns('sub.example.com'))),
        ).toBeDefined()
        // ... and could match an excluded name
        expect(
            checkNameConstraints(wildcard, exclude(dns('secret.example.com'))),
        ).toBeDefined()
        expect(
            checkNameConstraints(wildcard, exclude(dns('other.org'))),
        ).toBeUndefined()
    })

    test('iPAddress constraints', async () => {
        const constraints = permit(
            new iPAddress({
                bytes: new Uint8Array([192, 0, 2, 0, 255, 255, 255, 0]),
            }),
        )
        const at = (...octets: number[]) =>
            certificate({
                names: [new iPAddress({ bytes: new Uint8Array(octets) })],
            })
        expect(
            checkNameConstraints(await at(192, 0, 2, 9), constraints),
        ).toBeUndefined()
        expect(
            checkNameConstraints(await at(198, 51, 100, 1), constraints)?.type,
        ).toBe('iPAddress')
    })

    test('rfc822Name constraints, including the emailAddress in the subject', async () => {
        const constraints = permit(new rfc822Name({ value: 'example.com' }))
        expect(
            checkNameConstraints(
                await certificate({
                    names: [new rfc822Name({ value: 'a@example.com' })],
                }),
                constraints,
            ),
        ).toBeUndefined()
        expect(
            checkNameConstraints(
                await certificate({
                    names: [new rfc822Name({ value: 'a@evil.org' })],
                }),
                constraints,
            )?.type,
        ).toBe('rfc822Name')

        // an emailAddress attribute of the subject DN counts as an rfc822Name too
        const subjectEmail = await certificate({
            subject: 'CN=Alice, 1.2.840.113549.1.9.1=alice@evil.org',
        })
        expect(checkNameConstraints(subjectEmail, constraints)?.name).toBe(
            'alice@evil.org',
        )
    })

    test('URI constraints', async () => {
        const constraints = permit(
            new uniformResourceIdentifier({ value: '.example.com' }),
        )
        expect(
            checkNameConstraints(
                await certificate({
                    names: [
                        new uniformResourceIdentifier({
                            value: 'https://www.example.com/',
                        }),
                    ],
                }),
                constraints,
            ),
        ).toBeUndefined()
        expect(
            checkNameConstraints(
                await certificate({
                    names: [
                        new uniformResourceIdentifier({
                            value: 'https://www.evil.org/',
                        }),
                    ],
                }),
                constraints,
            )?.type,
        ).toBe('uniformResourceIdentifier')
    })

    test('directoryName constraints apply to the subject DN', async () => {
        const constraints = permit(
            directoryName.fromName(Name.parse('O=Example Org')),
        )
        expect(
            checkNameConstraints(
                await certificate({ subject: 'O=Example Org, CN=Alice' }),
                constraints,
            ),
        ).toBeUndefined()
        expect(
            checkNameConstraints(
                await certificate({ subject: 'O=Other, CN=Alice' }),
                constraints,
            )?.type,
        ).toBe('directoryName')
    })

    test('names it cannot evaluate fail closed', async () => {
        const other = () =>
            new otherName({
                typeID: '1.3.6.1.4.1.311.20.2.3',
                value: new asn1js.Utf8String({ value: 'user@example.com' }),
            })
        const constraints = permit(other())

        // the certificate has an otherName and the CA constrains otherNames
        expect(
            checkNameConstraints(
                await certificate({ names: [other()] }),
                constraints,
            )?.message,
        ).toContain('cannot check')
        // no otherName in the certificate: nothing to evaluate
        expect(
            checkNameConstraints(
                await certificate({ names: ['a.example.com'] }),
                constraints,
            ),
        ).toBeUndefined()
    })

    test('subtrees with minimum/maximum are refused (RFC 5280 forbids them)', async () => {
        const constraints = new NameConstraints({
            permittedSubtrees: [
                new GeneralSubtree({ base: dns('example.com'), minimum: 1 }),
            ],
        })
        expect(
            checkNameConstraints(
                await certificate({ names: ['a.example.com'] }),
                constraints,
            )?.message,
        ).toContain('minimum/maximum')
    })

    describe('common name fallback (stricter than RFC 5280)', () => {
        const constraints = permit(dns('example.com'))

        test('a host-like CN is checked when there is no dNSName', async () => {
            expect(
                checkNameConstraints(
                    await certificate({ subject: 'CN=www.evil.org' }),
                    constraints,
                )?.name,
            ).toBe('www.evil.org')
            expect(
                checkNameConstraints(
                    await certificate({ subject: 'CN=www.example.com' }),
                    constraints,
                ),
            ).toBeUndefined()
        })

        test('the CN is ignored once there is a dNSName', async () => {
            expect(
                checkNameConstraints(
                    await certificate({
                        subject: 'CN=www.evil.org',
                        names: ['www.example.com'],
                    }),
                    constraints,
                ),
            ).toBeUndefined()
        })

        test('a CN that is not a host name is not treated as one', async () => {
            expect(
                checkNameConstraints(
                    await certificate({ subject: 'CN=Example Server CA' }),
                    constraints,
                ),
            ).toBeUndefined()
        })
    })
})

describe('checkNameConstraints work limit', () => {
    const certWithNames = (count: number) =>
        Certificate.builder()
            .setSubject('CN=many.example')
            .setPublicKey(
                Certificate.fromPem(rsaSigningKeys.certPem).tbsCertificate
                    .subjectPublicKeyInfo,
            )
            .setPrivateKey(PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem))
            .setValidityDays(1)
            .addSubjectAltName(
                ...Array.from({ length: count }, (_, i) => `n${i}.example.com`),
            )
            .selfSign()
    const constraints = (count: number) =>
        new NameConstraints({
            permittedSubtrees: Array.from(
                { length: count },
                (_, i) =>
                    new GeneralSubtree({
                        base: new dNSName({
                            value: `c${i}.example.org`,
                        }),
                    }),
            ).concat(
                new GeneralSubtree({
                    base: new dNSName({ value: 'example.com' }),
                }),
            ),
        })

    test(`more than ${MAX_COMPARISONS} comparisons are rejected, not checked`, async () => {
        const cert = await certWithNames(500)
        // 500 names x 601 subtrees = 300,500 comparisons
        expect(checkNameConstraints(cert, constraints(600))?.message).toContain(
            'over the limit',
        )
        // 500 x 401 = 200,500: checked, and every name is permitted
        expect(checkNameConstraints(cert, constraints(400))).toBeUndefined()
    })
})
