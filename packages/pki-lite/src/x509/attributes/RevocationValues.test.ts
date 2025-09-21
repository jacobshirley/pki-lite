import { describe, test, expect } from 'vitest'
import { RevocationValues, OtherRevVals } from './RevocationValues.js'
import { CertificateList } from '../CertificateList.js'
import { BasicOCSPResponse } from '../../ocsp/BasicOCSPResponse.js'
import { asn1js } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { AttributeTypeAndValue } from '../AttributeTypeAndValue.js'
import { RelativeDistinguishedName } from '../RelativeDistinguishedName.js'
import { Name } from '../Name.js'
import { TBSCertList } from '../TBSCertList.js'
import { OCSPResponse } from '../../ocsp/OCSPResponse.js'
import { ResponseBytes } from '../../ocsp/ResponseBytes.js'
import { OCSPResponseStatus } from '../../ocsp/OCSPResponseStatus.js'
import { ResponseData } from '../../ocsp/ResponseData.js'



describe('RevocationValues', () => {
    test('encodes and decodes empty', () => {
        const rev = new RevocationValues({})
        const asn1 = rev.toAsn1()
        const decoded = RevocationValues.fromAsn1(asn1)
        expect(decoded.crlVals).toEqual([])
        expect(decoded.ocspVals).toEqual([])
        expect(decoded.otherRevVals).toEqual([])
    })

    test('encodes and decodes with CRL', () => {
        // Create issuer name
        const createName = (): Name => {
            const cn = new AttributeTypeAndValue({
                type: '2.5.4.3',
                value: 'Test CA',
            })
            const cnRdn = new RelativeDistinguishedName()
            cnRdn.push(cn)

            const name = new Name.RDNSequence()
            name.push(cnRdn)

            return name
        }

        // Create minimal CRL information
        const tbsCertList = new TBSCertList({
            signature: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }), // SHA256 with RSA
            issuer: createName(),
            thisUpdate: new Date(),
        })

        // Create signature (just a placeholder for testing)
        const signatureValue = new Uint8Array([10, 20, 30, 40, 50])

        // Create the CRL
        const crl = new CertificateList({
            tbsCertList,
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }), // SHA256 with RSA
            signatureValue,
        })
        const rev = new RevocationValues({ crlVals: [crl] })
        const asn1 = rev.toAsn1()
        const decoded = RevocationValues.fromAsn1(asn1)
        expect(decoded.crlVals?.length).toBe(1)
    })

    test('encodes and decodes with OCSP', () => {
        const responseStatus = OCSPResponseStatus.successful
        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const responseBytes = new ResponseBytes({
            responseType,
            response: new BasicOCSPResponse({
                tbsResponseData: new ResponseData({
                    version: 1,
                    producedAt: new Date(),
                    responderID: Name.parse('CN=Test'),
                    responses: [],
                }),
                signatureAlgorithm: new AlgorithmIdentifier({
                    algorithm: '1.2.840.113549.1.1.11',
                }),
                signature: new Uint8Array([1, 2, 3]),
                certs: [],
            }),
        })

        const ocsp = new OCSPResponse({ responseStatus, responseBytes })
        const rev = new RevocationValues({
            ocspVals: [ocsp.getBasicOCSPResponse()],
        })
        const asn1 = rev.toAsn1()
        const decoded = RevocationValues.fromAsn1(asn1)
        expect(decoded.ocspVals?.length).toBe(1)
    })

    test('encodes and decodes with OtherRevVals', () => {
        const other = new OtherRevVals({
            OtherRevValType: '1.2.3.4',
            OtherRevVals: new Uint8Array([1, 2, 3]),
        })
        const rev = new RevocationValues({ otherRevVals: [other] })
        const asn1 = rev.toAsn1()
        const decoded = RevocationValues.fromAsn1(asn1)
        expect(decoded.otherRevVals?.length).toBe(1)
        expect(decoded.otherRevVals?.[0].OtherRevValType.value).toBe('1.2.3.4')
    })

    test('toString does not throw', () => {
        const rev = new RevocationValues({})
        expect(() => rev.toString()).not.toThrow()
    })
})
