import { describe, it, expect } from 'vitest'
import { RevocationInfoArchival } from './RevocationInfoArchival.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { ResponseBytes } from '../ocsp/ResponseBytes.js'
import { OCSPResponseStatus } from '../ocsp/OCSPResponseStatus.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { TBSCertList } from '../x509/TBSCertList.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'
import { OtherRevInfo } from './OtherRevInfo.js'

describe('RevocationInfoArchival', () => {
    // Helper function to create a real CertificateList
    function createTestCRL(): CertificateList {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test CA',
        })
        const cnRdn = new RelativeDistinguishedName()
        cnRdn.push(cn)

        const name = new Name.RDNSequence()
        name.push(cnRdn)

        const tbsCertList = new TBSCertList({
            signature: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }),
            issuer: name,
            thisUpdate: new Date('2025-01-01'),
            nextUpdate: new Date('2026-01-01'),
            version: 1 as 1,
        })

        return new CertificateList({
            tbsCertList,
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }),
            signatureValue: new Uint8Array([1, 2, 3, 4]),
        })
    }

    // Helper function to create a real OCSPResponse
    function createTestOCSPResponse(): OCSPResponse {
        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const response = new Uint8Array([1, 2, 3, 4, 5])
        const responseBytes = new ResponseBytes({ responseType, response })

        return new OCSPResponse({
            responseStatus: OCSPResponseStatus.successful,
            responseBytes,
        })
    }

    // Helper function to create a real OtherRevInfo
    function createTestOtherRevInfo(): OtherRevInfo {
        return new OtherRevInfo({
            type: '1.2.3.4.5',
            value: new Uint8Array([6, 7, 8, 9, 10]),
        })
    }
    it('should instantiate with empty options', () => {
        const ria = new RevocationInfoArchival({})
        expect(ria.crls).toBeUndefined()
        expect(ria.ocsps).toBeUndefined()
        expect(ria.otherRevInfo).toBeUndefined()
    })

    it('should instantiate with all options', () => {
        const crl = createTestCRL()
        const ocsp = createTestOCSPResponse()
        const ori = createTestOtherRevInfo()
        const ria = new RevocationInfoArchival({
            crls: [crl],
            ocsps: [ocsp],
            otherRevInfo: [ori],
        })
        expect(ria.crls).toHaveLength(1)
        expect(ria.ocsps).toHaveLength(1)
        expect(ria.otherRevInfo).toHaveLength(1)
    })

    it('should convert to ASN.1 sequence', () => {
        const crl = createTestCRL()
        const ocsp = createTestOCSPResponse()
        const ori = createTestOtherRevInfo()
        const ria = new RevocationInfoArchival({
            crls: [crl],
            ocsps: [ocsp],
            otherRevInfo: [ori],
        })
        const asn1 = ria.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3)
        expect(ria.toString()).toMatchInlineSnapshot(`
          "[RevocationInfoArchival] SEQUENCE :
            [0] :
              SEQUENCE :
                SEQUENCE :
                  SEQUENCE :
                    INTEGER : 1
                    SEQUENCE :
                      OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
                    SEQUENCE :
                      SET :
                        SEQUENCE :
                          OBJECT IDENTIFIER : 2.5.4.3
                          PrintableString : 'Test CA'
                    UTCTime : 2025-01-01T00:00:00.000Z
                    UTCTime : 2026-01-01T00:00:00.000Z
                  SEQUENCE :
                    OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
                  BIT STRING : 00000001000000100000001100000100
            [1] :
              SEQUENCE :
                SEQUENCE :
                  ENUMERATED : 0
                  [0] :
                    SEQUENCE :
                      OBJECT IDENTIFIER : 1.3.6.1.5.5.7.48.1.1
                      OCTET STRING : 0102030405
            [2] :
              SEQUENCE :
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.3.4.5
                  OBJECT IDENTIFIER : empty"
    `)
    })

    it('should throw if fromAsn1 is not a sequence', () => {
        expect(() =>
            RevocationInfoArchival.fromAsn1(new asn1js.Null()),
        ).toThrow('Invalid ASN.1 structure: expected SEQUENCE')
    })
})
