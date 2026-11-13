import { beforeAll, describe, expect, test } from 'vitest'
import { opensslOcspPki, OcspPkiName } from '../../test-fixtures/openSsl.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { PrivateKeyInfo } from '../../src/keys/PrivateKeyInfo.js'
import { OCSPRequest } from '../../src/ocsp/OCSPRequest.js'
import { OCSPResponse } from '../../src/ocsp/OCSPResponse.js'
import { CertID } from '../../src/ocsp/CertID.js'
import { AlgorithmIdentifier } from '../../src/algorithms/AlgorithmIdentifier.js'
import { CertificateValidator } from '../../src/core/CertificateValidator.js'

/**
 * OCSP (RFC 6960) checked against OpenSSL, both ways: OpenSSL reads what pki-lite builds
 * and pki-lite reads what OpenSSL builds, and for the relying-party cases (which
 * responses may be trusted for a certificate's status) OpenSSL's verdict is checked
 * alongside pki-lite's, so the expectation does not rest on pki-lite alone.
 */

type Pki = Awaited<ReturnType<typeof opensslOcspPki>>
let pki: Pki
const cert = (name: OcspPkiName) => Certificate.fromPem(pki.pem(name))
const key = (name: OcspPkiName) => PrivateKeyInfo.fromPem(pki.key(name))
const hex = (bytes: Uint8Array) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
const DAY = 24 * 60 * 60 * 1000
/** A time `offset` ms from now, in whole seconds */
const wholeSeconds = (offset: number) =>
    new Date(Math.floor((Date.now() + offset) / 1000) * 1000)

/** The CertID in a request OpenSSL made for `name` */
const opensslCertId = async (name: OcspPkiName) =>
    OCSPRequest.fromDer(new Uint8Array(await pki.request({ cert: name })))
        .tbsRequest.requestList[0].reqCert

/**
 * pki-lite tests that do not pass yet, each with the reason. They run as `test.fails`,
 * so fixing one makes its test fail with "expected to fail": delete the entry then.
 */
const KEY_HASH =
    "CertID.forCertificate hashes the issuer key's whole BIT STRING encoding (tag, length and unused-bits octet included) instead of only the key bits (RFC 6960 4.1.1), so responders do not recognise pki-lite's CertIDs."
const FRACTIONAL_SECONDS =
    'OCSP times are written with fractional seconds (e.g. 08:03:23.166Z), which RFC 6960 / RFC 5280 GeneralizedTime forbids; OpenSSL rejects the thisUpdate and nextUpdate.'
const NOT_VERIFIED =
    "CertificateValidator matches OCSP responses by serial number alone: it does not check the response's signature, that the signer is the CA or a responder it authorised (OCSPSigning), or that the CertID's issuer hashes are this certificate's issuer."
const NOT_CURRENT =
    "CertificateValidator does not check a response's thisUpdate/nextUpdate, so an expired status is used."
const UNSUCCESSFUL =
    'CertificateValidator throws on an unsuccessful OCSP response (no responseBytes) instead of ignoring it.'

const KNOWN_ISSUES: Record<string, string> = {
    "CertID matches OpenSSL's (sha1)": KEY_HASH,
    "CertID matches OpenSSL's (sha256)": KEY_HASH,
    'OpenSSL reads our request and answers it': KEY_HASH,
    'signed by the CA': FRACTIONAL_SECONDS,
    'signed by a delegated responder': FRACTIONAL_SECONDS,
    'pki-lite: signed by a certificate of the CA without OCSPSigning':
        NOT_VERIFIED,
    'pki-lite: signed by an unrelated CA': NOT_VERIFIED,
    "pki-lite: another CA's good status for the same serial": NOT_VERIFIED,
    'pki-lite: a status past its nextUpdate': NOT_CURRENT,
    'pki-lite: an unsuccessful response (tryLater)': UNSUCCESSFUL,
}

const check = (name: string, fn: () => Promise<void>) =>
    (KNOWN_ISSUES[name] ? test.fails : test)(name, fn, 60_000)

describe('OCSP against OpenSSL', () => {
    beforeAll(async () => {
        pki = await opensslOcspPki()
    }, 120_000)

    describe('requests', () => {
        for (const hash of ['sha1', 'sha256'] as const) {
            check(`CertID matches OpenSSL's (${hash})`, async () => {
                const request = OCSPRequest.fromDer(
                    new Uint8Array(await pki.request({ cert: 'good', hash })),
                )
                const ours = await CertID.forCertificate(
                    cert('ca'),
                    cert('good'),
                    AlgorithmIdentifier.digestAlgorithm(
                        hash === 'sha1' ? 'SHA-1' : 'SHA-256',
                    ),
                )
                const theirs = request.tbsRequest.requestList[0].reqCert
                // the hash algorithm's NULL parameters may be present or absent
                expect(ours.hashAlgorithm.algorithm.value).toBe(
                    theirs.hashAlgorithm.algorithm.value,
                )
                expect(hex(ours.issuerNameHash.bytes)).toBe(
                    hex(theirs.issuerNameHash.bytes),
                )
                // RFC 6960 4.1.1: the hash of the key bits, without the BIT STRING
                // tag, length and unused-bits octet
                expect(hex(ours.issuerKeyHash.bytes)).toBe(
                    hex(theirs.issuerKeyHash.bytes),
                )
                expect(ours.serialNumber.toBigInt()).toBe(
                    theirs.serialNumber.toBigInt(),
                )
            })
        }

        check('OpenSSL reads our request and answers it', async () => {
            const request = await OCSPRequest.forCertificate({
                certificate: cert('good'),
                issuerCertificate: cert('ca'),
            })
            expect(await pki.requestText(request.toDer())).toContain(
                'Serial Number: 1001',
            )
            const response = OCSPResponse.fromDer(
                new Uint8Array(await pki.respond({ request: request.toDer() })),
            )
            // "unknown" would mean the responder did not recognise our CertID
            expect(
                response.getBasicOCSPResponse().tbsResponseData.responses[0]
                    .certStatus.status,
            ).toBe('good')
        })

        test('OpenSSL requests round-trip', async () => {
            const bytes = new Uint8Array(await pki.request({ cert: 'good' }))
            expect(hex(OCSPRequest.fromDer(bytes).toDer())).toBe(hex(bytes))
        })
    })

    describe("OpenSSL's responses", () => {
        test('a good status signed by the CA', async () => {
            const bytes = await pki.respond({
                request: await pki.request({ cert: 'good' }),
            })
            const response = OCSPResponse.fromDer(new Uint8Array(bytes))
            expect(response.responseStatus.value).toBe(0)
            const basic = response.getBasicOCSPResponse()
            const [single] = basic.tbsResponseData.responses
            expect(single.certStatus.status).toBe('good')
            expect(single.nextUpdate).toBeDefined()
            expect(hex(single.certID.toDer())).toBe(
                hex((await opensslCertId('good')).toDer()),
            )
            expect(hex(response.toDer())).toBe(hex(bytes))
        })

        test('a revoked status signed by a delegated responder', async () => {
            const bytes = await pki.respond({
                request: await pki.request({ cert: 'revoked' }),
                signer: 'responder',
            })
            const response = OCSPResponse.fromDer(new Uint8Array(bytes))
            const basic = response.getBasicOCSPResponse()
            const { certStatus } = basic.tbsResponseData.responses[0]
            expect(certStatus.status).toBe('revoked')
            expect(certStatus.revocationTime).toEqual(
                new Date('2025-01-01T00:00:00Z'),
            )
            expect(certStatus.revocationReason).toBe(1) // keyCompromise
            // the responder's certificate travels with the response
            expect(basic.certs?.some((c) => c.equals(cert('responder')))).toBe(
                true,
            )
            expect(hex(response.toDer())).toBe(hex(bytes))
        })
    })

    describe('responses pki-lite signs, verified by OpenSSL', () => {
        const build = async (options: {
            signer: OcspPkiName
            status: 'good' | 'revoked'
            for: OcspPkiName
            /** times in whole seconds, as RFC 5280 GeneralizedTime requires */
            whole?: boolean
        }) => {
            const time = (offset: number) =>
                options.whole
                    ? wholeSeconds(offset)
                    : new Date(Date.now() + offset)
            const builder = OCSPResponse.builder()
                .setPrivateKey(key(options.signer))
                .setResponderFromCertificate(cert(options.signer))
                .addResponse(await opensslCertId(options.for), options.status, {
                    thisUpdate: time(-60_000),
                    nextUpdate: time(DAY),
                    ...(options.status === 'revoked'
                        ? {
                              revocationTime: new Date('2025-01-01T00:00:00Z'),
                              revocationReason: 1,
                          }
                        : {}),
                })
            builder.setProducedAt(time(0))
            if (options.signer !== 'ca')
                builder.addCertificate(cert(options.signer))
            return (await builder.build()).toDer()
        }

        check('signed by the CA', async () => {
            const result = await pki.verify({
                response: await build({
                    signer: 'ca',
                    status: 'good',
                    for: 'good',
                }),
                cert: 'good',
            })
            expect(result.verified, result.output).toBe(true)
            expect(result.status, result.output).toBe('good')
        })

        check('signed by the CA, with times in whole seconds', async () => {
            const result = await pki.verify({
                response: await build({
                    signer: 'ca',
                    status: 'good',
                    for: 'good',
                    whole: true,
                }),
                cert: 'good',
            })
            expect(result.verified, result.output).toBe(true)
            expect(result.status, result.output).toBe('good')
        })

        check('signed by a delegated responder', async () => {
            const result = await pki.verify({
                response: await build({
                    signer: 'responder',
                    status: 'revoked',
                    for: 'revoked',
                }),
                cert: 'revoked',
            })
            expect(result.verified, result.output).toBe(true)
            expect(result.status, result.output).toBe('revoked')
        })
    })

    /**
     * Which responses a relying party may use for a certificate's status (RFC 6960 3.2,
     * 4.2.2.2): signed by the CA or by a responder it authorised (OCSPSigning), about this
     * certificate from this issuer, current, and successful. OpenSSL's verdict is the
     * oracle; pki-lite (CertificateValidator with checkOCSP) must agree.
     */
    describe('relying party: which responses count', () => {
        type Case = {
            name: string
            cert: OcspPkiName
            response: () => Promise<Uint8Array>
            /** whether a relying party may use the response (and the status it gives) */
            usable: false | 'good' | 'revoked'
            /** what OpenSSL reports, as a check on `usable` */
            openssl: (result: Awaited<ReturnType<Pki['verify']>>) => void
        }

        const cases: Case[] = [
            {
                name: 'good, signed by the CA',
                cert: 'good',
                response: async () =>
                    pki.respond({
                        request: await pki.request({ cert: 'good' }),
                    }),
                usable: 'good',
                openssl: (r) => {
                    expect(r.verified, r.output).toBe(true)
                    expect(r.status).toBe('good')
                },
            },
            {
                name: 'revoked, signed by a delegated responder',
                cert: 'revoked',
                response: async () =>
                    pki.respond({
                        request: await pki.request({ cert: 'revoked' }),
                        signer: 'responder',
                    }),
                usable: 'revoked',
                openssl: (r) => {
                    expect(r.verified, r.output).toBe(true)
                    expect(r.status).toBe('revoked')
                },
            },
            {
                name: 'signed by a certificate of the CA without OCSPSigning',
                cert: 'good',
                response: async () =>
                    pki.respond({
                        request: await pki.request({ cert: 'good' }),
                        signer: 'notResponder',
                    }),
                usable: false,
                openssl: (r) => {
                    expect(r.verified).toBe(false)
                    expect(r.output).toContain('missing ocspsigning usage')
                },
            },
            {
                name: 'signed by an unrelated CA',
                cert: 'good',
                response: async () =>
                    pki.respond({
                        request: await pki.request({ cert: 'good' }),
                        signer: 'otherCa',
                    }),
                usable: false,
                openssl: (r) => expect(r.verified).toBe(false),
            },
            {
                // the danger: a genuine "good" for the same serial from another issuer
                name: "another CA's good status for the same serial",
                cert: 'revoked',
                response: async () =>
                    pki.respond({
                        request: await pki.request({
                            cert: 'otherCaSameSerial',
                            issuer: 'otherCa',
                        }),
                        ca: 'otherCa',
                    }),
                usable: false,
                openssl: (r) => {
                    expect(r.status).toBeUndefined()
                    expect(r.output).toContain('No Status found')
                },
            },
            {
                name: 'a status past its nextUpdate',
                cert: 'good',
                response: async () =>
                    (
                        await OCSPResponse.builder()
                            .setPrivateKey(key('ca'))
                            .setResponderFromCertificate(cert('ca'))
                            // whole seconds, so stale is OpenSSL's only complaint
                            .setProducedAt(wholeSeconds(-30 * DAY))
                            .addResponse(await opensslCertId('good'), 'good', {
                                thisUpdate: wholeSeconds(-30 * DAY),
                                nextUpdate: wholeSeconds(-23 * DAY),
                            })
                            .build()
                    ).toDer(),
                usable: false,
                openssl: (r) => {
                    expect(r.output).toContain('Status times invalid')
                    expect(r.output).toContain('status expired')
                    expect(r.output).not.toContain('error in thisupdate field')
                },
            },
            {
                name: 'an unsuccessful response (tryLater)',
                cert: 'good',
                response: async () =>
                    (
                        await OCSPResponse.builder()
                            .setResponseStatus(3)
                            .build()
                    ).toDer(),
                usable: false,
                openssl: (r) => {
                    expect(r.status).toBeUndefined()
                    expect(r.output).toContain('trylater')
                },
            },
        ]

        for (const c of cases) {
            test(`OpenSSL: ${c.name}`, async () => {
                c.openssl(
                    await pki.verify({
                        response: await c.response(),
                        cert: c.cert,
                    }),
                )
            }, 60_000)

            check(`pki-lite: ${c.name}`, async () => {
                const result = await new CertificateValidator().validate(
                    cert(c.cert),
                    { checkOCSP: true },
                    {
                        ocspResponses: [
                            OCSPResponse.fromDer(
                                new Uint8Array(await c.response()),
                            ),
                        ],
                        issuerCertificate: cert('ca'),
                    },
                )
                if (c.usable) {
                    expect(result.revocationStatus.source).toBe('OCSP')
                    expect(result.revocationStatus.isRevoked).toBe(
                        c.usable === 'revoked',
                    )
                } else {
                    // the response must not be relied on for the status
                    expect(
                        result.revocationStatus.source,
                        result.revocationStatus.details,
                    ).not.toBe('OCSP')
                }
            })
        }
    })
})
