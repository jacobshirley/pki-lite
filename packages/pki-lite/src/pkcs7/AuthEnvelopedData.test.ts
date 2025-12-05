import { AuthEnvelopedData } from './AuthEnvelopedData.js'
import { Certificate } from '../x509/Certificate.js'
import { test, expect, describe } from 'vitest'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { CMSVersion } from './CMSVersion.js'
import { KeyTransRecipientInfo } from './recipients/KeyTransRecipientInfo.js'
import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'

describe('AuthEnvelopedData', () => {
    test('AuthEnvelopedData should correctly serialize and deserialize', () => {
        // Create a simple algorithm identifier
        const algId = new AlgorithmIdentifier({
            algorithm: OIDs.ENCRYPTION.AES_256_GCM,
        })

        // Create encrypted content info
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: algId,
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        // Create a recipient info
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: cert.tbsCertificate.issuer,
            serialNumber: cert.tbsCertificate.serialNumber,
        })
        const keyTransRecipientInfo = new KeyTransRecipientInfo({
            version: CMSVersion.v0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: OIDs.RSA.ENCRYPTION,
            }),
            encryptedKey: new Uint8Array([10, 20, 30, 40]),
        })

        // Create a message authentication code
        const mac = new Uint8Array([5, 4, 3, 2, 1])

        // Create AuthEnvelopedData
        const authEnvelopedData = new AuthEnvelopedData({
            version: CMSVersion.v0,
            recipientInfos: [keyTransRecipientInfo],
            authEncryptedContentInfo: encryptedContentInfo,
            mac,
        })

        // Convert to ASN.1 and back
        const asn1 = authEnvelopedData.toAsn1()
        const parsedAuthEnvelopedData = AuthEnvelopedData.fromAsn1(asn1)

        // Wrap in CMS ContentInfo
        const cms = parsedAuthEnvelopedData.toCms()

        expect(cms.toString()).toMatchInlineSnapshot(`
          "[ContentInfo] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.9.16.1.23
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
                      INTEGER : 40829422232738761675369452088356448433387579930
                    SEQUENCE :
                      OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                    OCTET STRING : 0a141e28
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.16.840.1.101.3.4.1.46
                  [CONTEXT 0] PRIMITIVE (5 bytes)
                OCTET STRING : 0504030201"
        `)
    })
})
