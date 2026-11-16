import { describe, expect, test } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048'
import { Certificate } from '../../src/x509/Certificate'
import { AuthorityInfoAccess } from '../../src/x509/extensions/AuthorityInfoAccess'
import { Extension } from '../../src/x509/Extension'
import { GeneralName } from '../../src/x509/GeneralName'
import { OctetString } from '../../src/asn1/OctetString'
import { OIDs } from '../../src/core/OIDs'
import { OCSPRequest } from '../../src/ocsp/OCSPRequest'
import { OCSPResponse } from '../../src/ocsp/OCSPResponse'
import { PrivateKeyInfo } from '../../src/keys/PrivateKeyInfo'
import http from 'http'
import { AddressInfo } from 'net'

/** A local HTTP OCSP responder answering each request with `answer(request body)`. */
const responder = (answer: (body: Uint8Array) => Promise<Uint8Array>) =>
    new Promise<{ url: string; close: () => void }>((resolve) => {
        const server = http
            .createServer((req, res) => {
                const chunks: Buffer[] = []
                req.on('data', (chunk) => chunks.push(chunk))
                req.on('end', async () => {
                    const body = await answer(
                        new Uint8Array(Buffer.concat(chunks)),
                    )
                    res.writeHead(200, {
                        'Content-Type': 'application/ocsp-response',
                    })
                    res.end(body)
                })
            })
            .listen(0, () =>
                resolve({
                    url: `http://localhost:${(server.address() as AddressInfo).port}/ocsp`,
                    close: () => server.close(),
                }),
            )
    })

describe('OCSP (Online Certificate Status Protocol)', () => {
    test('requestOcsp sends a nonce and takes a response that echoes it', async () => {
        const key = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const publicKey = Certificate.fromPem(rsaSigningKeys.certPem)
            .tbsCertificate.subjectPublicKeyInfo
        const ca = await Certificate.builder()
            .setSubject('CN=OCSP Fetch CA')
            .setPublicKey(publicKey)
            .setPrivateKey(key)
            .setValidityDays(1)
            .addBasicConstraints(true)
            .addKeyUsage({ keyCertSign: true, cRLSign: true })
            .selfSign()

        let sentNonce: Uint8Array | undefined
        const server = await responder(async (body) => {
            const request = OCSPRequest.fromDer(new Uint8Array(body))
            sentNonce = request.nonce
            const builder = OCSPResponse.builder()
                .setPrivateKey(key)
                .setResponderFromCertificate(ca)
                .addResponse(request.tbsRequest.requestList[0].reqCert, 'good')
            if (request.nonce) {
                builder.addResponseExtension(
                    new Extension({
                        extnID: OIDs.PKIX.ID_PKIX_OCSP_NONCE,
                        extnValue: new OctetString({ bytes: request.nonce }),
                    }),
                )
            }
            return (await builder.build()).toDer()
        })
        try {
            const leaf = await Certificate.builder()
                .setSubject('CN=leaf')
                .setPublicKey(publicKey)
                .setIssuer(ca)
                .setIssuerPrivateKey(key)
                .setValidityDays(1)
                .addExtension(
                    Extension.authorityInfoAccess([
                        {
                            accessMethod: OIDs.AUTHORITY_INFO_ACCESS.OCSP,
                            accessLocation:
                                new GeneralName.uniformResourceIdentifier({
                                    value: server.url,
                                }),
                        },
                    ]),
                )
                .sign()

            const response = await leaf.requestOcsp({ issuerCertificate: ca })
            expect(sentNonce).toHaveLength(32)
            expect(response?.nonce).toEqual(sentNonce)
            expect(
                (await response?.getResponse(leaf, ca))?.certStatus.status,
            ).toBe('good')
        } finally {
            server.close()
        }
    })

    test("requestOcsp ignores a response with another request's nonce (a replay)", async () => {
        // a canned response, recorded with a nonce of its own
        const canned = OCSPResponse.fromDer(rsaSigningKeys.ocspResponse)
        expect(canned.nonce).toBeDefined()
        const server = await responder(async () => rsaSigningKeys.ocspResponse)
        try {
            const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
            expect(
                certificate.tbsCertificate
                    .getExtensionsByName('AUTHORITY_INFO_ACCESS')[0]
                    .extnValue.parseAs(AuthorityInfoAccess)
                    .map((ad) => ad.accessLocation.toString()),
            ).toEqual([
                'http://localhost:8080/ca.crt',
                'http://localhost:8080/ocsp',
                'http://localhost:8080/ocsp-backup',
            ])

            const ocsp = await certificate.requestOcsp({
                // only the local server: the certificate's own URLs are not running
                ocspResponderUrls: [server.url],
                issuerCertificate: Certificate.fromPem(
                    rsaSigningKeys.caCertPem,
                ),
            })
            expect(ocsp).toBeUndefined()
        } finally {
            server.close()
        }
    })
})
