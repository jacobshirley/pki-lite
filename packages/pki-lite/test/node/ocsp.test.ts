import { assert, describe, expect, test } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048'
import { Certificate } from '../../src/x509/Certificate'
import { AuthorityInfoAccess } from '../../src/x509/extensions/AuthorityInfoAccess'
import http from 'http'

describe('OCSP (Online Certificate Status Protocol)', () => {
    test('can retrieve an OCSP response from a certificate with an Authority Information Access extension', async () => {
        const server = http
            .createServer((req, res) => {
                res.writeHead(200, { 'Content-Type': 'application/pkix-crl' })
                res.end(rsaSigningKeys.ocspResponse)
                server.close()
            })
            .listen(0)
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

        // NB: This will only work if the OCSP responder is accessible
        const ocsp = await certificate.requestOcsp({
            ocspResponderUrls: [
                'http://localhost:' + (server.address() as any).port + '/ocsp',
            ],
            issuerCertificate: Certificate.fromPem(rsaSigningKeys.caCertPem),
        })

        assert(ocsp, 'No OCSP response found')
        expect(ocsp.toString()).toMatchInlineSnapshot(`
          "[OCSPResponse] SEQUENCE :
            ENUMERATED : 0
            [0] :
              SEQUENCE :
                OBJECT IDENTIFIER : 1.3.6.1.5.5.7.48.1.1
                OCTET STRING : 1771 bytes"
        `)
    })
})
