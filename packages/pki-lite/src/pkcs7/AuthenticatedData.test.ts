import { AuthenticatedData } from './AuthenticatedData.js'
import { Certificate } from '../x509/Certificate.js'
import { describe, test as example, expect, test } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { KeyTransRecipientInfo } from './recipients/KeyTransRecipientInfo.js'
import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'

describe('AuthenticatedData', () => {
    test('AuthenticatedData should correctly serialize and deserialize', () => {
        // Create a simple algorithm identifier for MAC
        const macAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.HASH.HMAC_SHA256,
        })

        // Create encapsulated content info
        const encapContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        // Create a recipient info
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: cert.tbsCertificate.issuer,
            serialNumber: cert.tbsCertificate.serialNumber,
        })
        const keyTransRecipientInfo = new KeyTransRecipientInfo({
            version: 0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: OIDs.RSA.ENCRYPTION,
            }),
            encryptedKey: new Uint8Array([10, 20, 30, 40]),
        })

        // Create a message authentication code
        const mac = new Uint8Array([5, 4, 3, 2, 1])

        // Create AuthenticatedData
        const authenticatedData = new AuthenticatedData({
            version: 0,
            recipientInfos: [keyTransRecipientInfo],
            macAlgorithm,
            encapContentInfo,
            mac,
        })

        // Convert to ASN.1 and back
        const asn1 = authenticatedData.toAsn1()
        const parsedAuthenticatedData = AuthenticatedData.fromAsn1(asn1)

        // Wrap in CMS ContentInfo
        const cms = authenticatedData.toCms()

        expect(parsedAuthenticatedData).toEqual(authenticatedData)
        expect(cms.toString()).toMatchInlineSnapshot(`
          "[ContentInfo] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.7.7
            [0] :
              SEQUENCE :
                INTEGER : 0
                SET :
                  SEQUENCE :
                    INTEGER : 0
                    SEQUENCE :
                      SEQUENCE :
                        SET :
                          SEQUENCE :
                            OBJECT IDENTIFIER : 2.5.4.6
                            PrintableString : 'US'
                        SET :
                          SEQUENCE :
                            OBJECT IDENTIFIER : 2.5.4.8
                            UTF8String : 'Test'
                        SET :
                          SEQUENCE :
                            OBJECT IDENTIFIER : 2.5.4.7
                            UTF8String : 'Local'
                        SET :
                          SEQUENCE :
                            OBJECT IDENTIFIER : 2.5.4.10
                            UTF8String : 'MyOrg'
                        SET :
                          SEQUENCE :
                            OBJECT IDENTIFIER : 2.5.4.11
                            UTF8String : 'CA'
                        SET :
                          SEQUENCE :
                            OBJECT IDENTIFIER : 2.5.4.3
                            UTF8String : 'MyRootCA'
                      INTEGER : 398928024258410044557557511117164742139576349660
                    SEQUENCE :
                      OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                    OCTET STRING : 0a141e28
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.2.9
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
                  [0] :
                    OCTET STRING : 0102030405
                OCTET STRING : 0504030201"
        `)
    })
})
