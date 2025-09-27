import { describe, it, expect, assert } from 'vitest'
import { EncryptedData } from './EncryptedData.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'

describe('EncryptedData', () => {
    it('should create EncryptedData', () => {
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const encryptedData = new EncryptedData({
            version: 1,
            encryptedContentInfo,
        })

        expect(encryptedData.version).toBe(1)
        expect(encryptedData.encryptedContentInfo).toBe(encryptedContentInfo)
    })

    it('should convert to ASN.1 structure', () => {
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const encryptedData = new EncryptedData({
            version: 1,
            encryptedContentInfo,
        })
        const asn1 = encryptedData.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value).toHaveLength(2) // version, encryptedContentInfo
    })

    it('should convert to string', () => {
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
        })

        const encryptedData = new EncryptedData({
            version: 1,
            encryptedContentInfo,
        })
        const str = encryptedData.toString()

        expect(typeof str).toBe('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('should parse from ASN.1 structure', () => {
        const originalEncryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const originalEncryptedData = new EncryptedData({
            version: 1,
            encryptedContentInfo: originalEncryptedContentInfo,
        })
        const asn1 = originalEncryptedData.toAsn1()

        const parsedEncryptedData = EncryptedData.fromAsn1(asn1)

        expect(parsedEncryptedData.version).toBe(originalEncryptedData.version)
        expect(parsedEncryptedData.encryptedContentInfo.contentType).toEqual(
            originalEncryptedData.encryptedContentInfo.contentType,
        )

        // Compare encrypted content
        expect(
            parsedEncryptedData.encryptedContentInfo.encryptedContent,
        ).toEqual(originalEncryptedData.encryptedContentInfo.encryptedContent)
    })

    it('EncryptedData toString snapshot', () => {
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const obj = new EncryptedData({ version: 1, encryptedContentInfo })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[EncryptedData] SEQUENCE :
            INTEGER : 1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              SEQUENCE :
                OBJECT IDENTIFIER : 2.16.840.1.101.3.4.1.2
              OCTET STRING : 0102030405"
        `)
    })

    it('EncryptedData toPem snapshot', () => {
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const obj = new EncryptedData({ version: 1, encryptedContentInfo })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ENCRYPTEDDATA-----
          MCQCAQEwHwYJKoZIhvcNAQcBMAsGCWCGSAFlAwQBAoAFAQIDBAU=
          -----END ENCRYPTEDDATA-----"
        `)
    })

    it('EncryptedContentInfo toString snapshot', () => {
        const obj = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[EncryptedContentInfo] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
            SEQUENCE :
              OBJECT IDENTIFIER : 2.16.840.1.101.3.4.1.2
            OCTET STRING : 0102030405"
        `)
    })

    it('EncryptedContentInfo toPem snapshot', () => {
        const obj = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ENCRYPTEDCONTENTINFO-----
          MB8GCSqGSIb3DQEHATALBglghkgBZQMEAQKABQECAwQF
          -----END ENCRYPTEDCONTENTINFO-----"
        `)
    })
})
