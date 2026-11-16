import { describe, expect, test, beforeAll } from 'vitest'
import { CrlChecker, CrlCheckerOptions } from './CrlChecker.js'
import { OIDs } from './OIDs.js'
import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { Extension } from '../x509/Extension.js'
import { CRLReason } from '../x509/CRLReason.js'
import { ReasonFlags } from '../x509/ReasonFlags.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { directoryName, GeneralNames } from '../x509/GeneralName.js'
import { Integer } from '../asn1/Integer.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import {
    CRLDistributionPoints,
    DistributionPoint,
} from '../x509/extensions/CRLDistributionPoints.js'
import { IssuingDistributionPoint } from '../x509/extensions/IssuingDistributionPoint.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { rsaSigningKeys as otherRsaKeys } from '../../test-fixtures/signing-keys/rsa-3072/index.js'
import { SignatureAlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'

const caKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
const caPublicKey = Certificate.fromPem(rsaSigningKeys.certPem).tbsCertificate
    .subjectPublicKeyInfo
const otherKey = PrivateKeyInfo.fromPem(otherRsaKeys.privateKeyPem)

const NOW = new Date('2026-06-01T00:00:00Z')
const BEFORE = new Date('2026-01-01T00:00:00Z')
const AFTER = new Date('2027-01-01T00:00:00Z')

const dpName = (cn: string) =>
    new GeneralNames(directoryName.fromName(RDNSequence.parse(`CN=${cn}`)))

const ext = (
    oid: string,
    value: Integer | CRLReason | IssuingDistributionPoint,
    critical = false,
) => new Extension({ extnID: oid, critical, extnValue: value })

const crlNumber = (n: number) =>
    ext(OIDs.EXTENSION.CRL_NUMBER, new Integer({ value: n }))
const deltaOf = (n: number) =>
    ext(OIDs.EXTENSION.DELTA_CRL_INDICATOR, new Integer({ value: n }), true)
const idp = (
    options: ConstructorParameters<typeof IssuingDistributionPoint>[0],
) =>
    ext(
        OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
        new IssuingDistributionPoint(options),
        true,
    )
const reason = (code: number) => [
    ext(OIDs.EXTENSION.CRL_REASON_CODE, new CRLReason(code)),
]

let ca: Certificate
let ee: Certificate

async function issueCa(
    subject: string,
    keyUsage = { keyCertSign: true, cRLSign: true },
) {
    return Certificate.builder()
        .setSubject(subject)
        .setPublicKey(caPublicKey)
        .setPrivateKey(caKey)
        .setValidityPeriod(new Date('2024-01-01'), new Date('2030-01-01'))
        .addBasicConstraints(true)
        .addKeyUsage(keyUsage)
        .selfSign()
}

async function issueEe(extensions: Extension[] = []) {
    return Certificate.builder()
        .setSubject('CN=End Entity')
        .setPublicKey(caPublicKey)
        .setIssuer(ca)
        .setIssuerPrivateKey(caKey)
        .setSerialNumber(42)
        .setValidityPeriod(new Date('2024-01-01'), new Date('2030-01-01'))
        .addExtensions(...extensions)
        .sign()
}

async function crl(
    options: {
        thisUpdate?: Date
        nextUpdate?: Date | null
        revoked?: { serial: number; extensions?: Extension[] }[]
        extensions?: Extension[]
        issuer?: Certificate
        key?: PrivateKeyInfo
    } = {},
) {
    const builder = CertificateList.builder()
        .setIssuerFromCertificate(options.issuer ?? ca)
        .setPrivateKey(options.key ?? caKey)
        .setThisUpdate(options.thisUpdate ?? BEFORE)
    builder.setNextUpdate(options.nextUpdate ?? AFTER)
    for (const entry of options.revoked ?? []) {
        builder.addRevokedCertificate({
            serialNumber: entry.serial,
            revocationDate: BEFORE,
            crlEntryExtensions: entry.extensions,
        })
    }
    builder.addExtensions(...(options.extensions ?? [crlNumber(1)]))
    const built = await builder.build()
    if (options.nextUpdate === null) {
        // the builder always sets nextUpdate: take it out and sign again
        built.tbsCertList.nextUpdate = undefined
        built.signatureValue.bytes = await new SignatureAlgorithmIdentifier(
            built.signatureAlgorithm,
        ).sign(built.tbsCertList, options.key ?? caKey)
    }
    // parse it back, as a relying party would
    return CertificateList.fromDer(built.toDer())
}

const check = (
    crls: CertificateList[],
    certificate = ee,
    options: Partial<CrlCheckerOptions> = {},
) =>
    new CrlChecker({
        crls,
        certificates: [ca],
        trustAnchors: [ca],
        time: NOW,
        validateSigner: async () => false,
        ...options,
    }).check(certificate)

describe('CrlChecker (RFC 5280 6.3)', () => {
    beforeAll(async () => {
        ca = await issueCa('CN=Test CA')
        ee = await issueEe()
    })

    describe('complete CRLs', () => {
        test('a current CRL from the issuer not listing the certificate: good', async () => {
            expect((await check([await crl()])).status).toBe('good')
        })

        test('a CRL listing the certificate: revoked, with reason and date', async () => {
            const result = await check([
                await crl({ revoked: [{ serial: 42, extensions: reason(1) }] }),
            ])
            expect(result.status).toBe('revoked')
            expect(result.reason).toBe(1)
            expect(result.revocationTime).toEqual(BEFORE)
        })

        test('another serial on the CRL does not revoke the certificate', async () => {
            expect(
                (await check([await crl({ revoked: [{ serial: 43 }] })]))
                    .status,
            ).toBe('good')
        })

        test('a revocation on any usable CRL counts, whatever the order', async () => {
            const clean = await crl({ extensions: [crlNumber(1)] })
            const listing = await crl({
                extensions: [crlNumber(2)],
                revoked: [{ serial: 42 }],
            })
            expect((await check([clean, listing])).status).toBe('revoked')
            expect((await check([listing, clean])).status).toBe('revoked')
        })

        test('no CRL: undetermined', async () => {
            expect((await check([])).status).toBe('undetermined')
        })

        test("another issuer's CRL listing the serial is not used", async () => {
            const other = await issueCa('CN=Other CA')
            const result = await check(
                [await crl({ issuer: other, revoked: [{ serial: 42 }] })],
                ee,
                { certificates: [ca, other], trustAnchors: [ca, other] },
            )
            expect(result.status).toBe('undetermined')
        })

        test('a CRL whose signature does not verify: undetermined', async () => {
            const result = await check([await crl({ key: otherKey })])
            expect(result.status).toBe('undetermined')
            expect(result.details).toMatch(/no valid signature/)
        })

        test('a CRL signed by a key without cRLSign: undetermined', async () => {
            ca = await issueCa('CN=Test CA', {
                keyCertSign: true,
                cRLSign: false,
            })
            try {
                expect((await check([await crl()])).status).toBe('undetermined')
            } finally {
                ca = await issueCa('CN=Test CA')
            }
        })
    })

    describe('freshness', () => {
        test('thisUpdate in the future: undetermined', async () => {
            const result = await check([
                await crl({
                    thisUpdate: AFTER,
                    nextUpdate: new Date('2028-01-01'),
                }),
            ])
            expect(result.status).toBe('undetermined')
            expect(result.details).toMatch(/not yet valid/)
        })

        test('nextUpdate in the past: undetermined', async () => {
            const result = await check([
                await crl({
                    thisUpdate: new Date('2025-01-01'),
                    nextUpdate: BEFORE,
                }),
            ])
            expect(result.status).toBe('undetermined')
            expect(result.details).toMatch(/out of date/)
        })

        test('no nextUpdate: undetermined', async () => {
            const result = await check([await crl({ nextUpdate: null })])
            expect(result.status).toBe('undetermined')
            expect(result.details).toMatch(/no nextUpdate/)
        })
    })

    describe('critical extensions', () => {
        const unknown = (critical: boolean) =>
            ext('1.2.3.4.5', new Integer({ value: 1 }), critical)

        test('an unknown critical CRL extension makes the CRL unusable', async () => {
            const result = await check([
                await crl({ extensions: [crlNumber(1), unknown(true)] }),
            ])
            expect(result.status).toBe('undetermined')
        })

        test('an unknown non-critical CRL extension is ignored', async () => {
            const result = await check([
                await crl({ extensions: [crlNumber(1), unknown(false)] }),
            ])
            expect(result.status).toBe('good')
        })

        test('an unknown critical entry extension makes the CRL unusable', async () => {
            const result = await check([
                await crl({
                    revoked: [{ serial: 7, extensions: [unknown(true)] }],
                }),
            ])
            expect(result.status).toBe('undetermined')
        })
    })

    describe('CRL signers', () => {
        test('a signer that is not a trust anchor has its path validated', async () => {
            const crls = [await crl()]
            const asked: Certificate[] = []
            const options = (valid: boolean): Partial<CrlCheckerOptions> => ({
                trustAnchors: [],
                validateSigner: async (signer) => {
                    asked.push(signer)
                    return valid
                },
            })
            expect((await check(crls, ee, options(false))).status).toBe(
                'undetermined',
            )
            expect((await check(crls, ee, options(true))).status).toBe('good')
            expect(asked.every((signer) => signer.equals(ca))).toBe(true)
        })
    })

    describe('reasons', () => {
        test('a distribution point for some reasons does not cover the others', async () => {
            const limited = await issueEe([
                new Extension({
                    extnID: OIDs.EXTENSION.CRL_DISTRIBUTION_POINTS,
                    extnValue: new CRLDistributionPoints(
                        new DistributionPoint({
                            distributionPoint: dpName('dp1'),
                            reasons: new ReasonFlags({ keyCompromise: true }),
                        }),
                    ),
                }),
            ])
            const result = await check(
                [await crl({ extensions: [crlNumber(1)] })],
                limited,
            )
            expect(result.status).toBe('undetermined')
        })

        test('CRLs for some reasons each cover all reasons together', async () => {
            const crls = [
                await crl({
                    extensions: [
                        crlNumber(1),
                        idp({
                            onlySomeReasons: new ReasonFlags({
                                keyCompromise: true,
                                cACompromise: true,
                            }),
                        }),
                    ],
                }),
            ]
            expect((await check(crls)).status).toBe('undetermined')
            crls.push(
                await crl({
                    extensions: [
                        crlNumber(2),
                        idp({
                            onlySomeReasons: new ReasonFlags({
                                affiliationChanged: true,
                                superseded: true,
                                cessationOfOperation: true,
                                certificateHold: true,
                                privilegeWithdrawn: true,
                                aACompromise: true,
                            }),
                        }),
                    ],
                }),
            )
            expect((await check(crls)).status).toBe('good')
        })
    })

    describe('delta CRLs', () => {
        test('a delta CRL alone is not enough', async () => {
            const delta = await crl({ extensions: [crlNumber(2), deltaOf(1)] })
            expect((await check([delta])).status).toBe('undetermined')
        })

        test('a delta CRL on the complete CRL adds revocations', async () => {
            const base = await crl({ extensions: [crlNumber(5)] })
            const delta = await crl({
                extensions: [crlNumber(6), deltaOf(5)],
                revoked: [{ serial: 42, extensions: reason(1) }],
            })
            expect((await check([base, delta])).status).toBe('revoked')
        })

        test('a delta CRL for a later complete CRL is not applied', async () => {
            const base = await crl({ extensions: [crlNumber(5)] })
            const delta = await crl({
                extensions: [crlNumber(7), deltaOf(6)],
                revoked: [{ serial: 42 }],
            })
            expect((await check([base, delta])).status).toBe('good')
        })

        test('a delta CRL with another scope is not applied', async () => {
            const base = await crl({ extensions: [crlNumber(5)] })
            const delta = await crl({
                extensions: [
                    crlNumber(6),
                    deltaOf(5),
                    idp({ onlyContainsCACerts: true }),
                ],
                revoked: [{ serial: 42 }],
            })
            expect((await check([base, delta])).status).toBe('good')
        })

        test('removeFromCRL on a delta CRL lifts a hold', async () => {
            const base = await crl({
                extensions: [crlNumber(5)],
                revoked: [{ serial: 42, extensions: reason(6) }],
            })
            expect((await check([base])).status).toBe('revoked')
            const delta = await crl({
                extensions: [crlNumber(6), deltaOf(5)],
                revoked: [{ serial: 42, extensions: reason(8) }],
            })
            expect((await check([base, delta])).status).toBe('good')
        })
    })

    describe('issuingDistributionPoint scope', () => {
        test('onlyContainsCACerts does not cover an end entity', async () => {
            const result = await check([
                await crl({
                    extensions: [
                        crlNumber(1),
                        idp({ onlyContainsCACerts: true }),
                    ],
                }),
            ])
            expect(result.status).toBe('undetermined')
        })

        test('onlyContainsUserCerts covers an end entity', async () => {
            const result = await check([
                await crl({
                    extensions: [
                        crlNumber(1),
                        idp({ onlyContainsUserCerts: true }),
                    ],
                }),
            ])
            expect(result.status).toBe('good')
        })

        test('a CRL for another distribution point does not cover the certificate', async () => {
            const withDp = await issueEe([
                new Extension({
                    extnID: OIDs.EXTENSION.CRL_DISTRIBUTION_POINTS,
                    extnValue: new CRLDistributionPoints(
                        new DistributionPoint({
                            distributionPoint: dpName('dp1'),
                        }),
                    ),
                }),
            ])
            const forDp = (cn: string) =>
                crl({
                    extensions: [
                        crlNumber(1),
                        idp({ distributionPoint: dpName(cn) }),
                    ],
                })
            expect((await check([await forDp('dp2')], withDp)).status).toBe(
                'undetermined',
            )
            expect((await check([await forDp('dp1')], withDp)).status).toBe(
                'good',
            )
        })
    })

    describe('strictProfile (RFC 5280 section 5)', () => {
        const strict = { strictProfile: true }

        test('a CRL without a cRLNumber, or with a critical one, is not used', async () => {
            const without = await crl({ extensions: [] })
            expect((await check([without])).status).toBe('good')
            expect((await check([without], ee, strict)).status).toBe(
                'undetermined',
            )
            const critical = await crl({
                extensions: [
                    new Extension({
                        extnID: OIDs.EXTENSION.CRL_NUMBER,
                        critical: true,
                        extnValue: new Integer({ value: 1 }),
                    }),
                ],
            })
            expect((await check([critical], ee, strict)).details).toMatch(
                /critical cRLNumber/,
            )
        })

        test('a CRL listing a serial number twice is not used', async () => {
            const twice = await crl({ revoked: [{ serial: 7 }, { serial: 7 }] })
            expect((await check([twice])).status).toBe('good')
            expect((await check([twice], ee, strict)).details).toMatch(/twice/)
        })
    })
})
