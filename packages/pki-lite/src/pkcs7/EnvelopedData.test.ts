import { describe, it, expect } from 'vitest'
import { EnvelopedData } from './EnvelopedData.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'

describe('EnvelopedData', () => {
    it('should create EnvelopedData', () => {
        const recipientInfos: any[] = []
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const envelopedData = new EnvelopedData({
            version: 0,
            recipientInfos,
            encryptedContentInfo,
        })

        expect(envelopedData).toBeInstanceOf(EnvelopedData)
        expect(envelopedData.version).toEqual(0)
        expect(envelopedData.recipientInfos).toBeDefined()
        expect(envelopedData.encryptedContentInfo).toEqual(encryptedContentInfo)
    })

    it('should convert to ASN.1 structure', () => {
        const recipientInfos: any[] = []
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const envelopedData = new EnvelopedData({
            version: 0,
            recipientInfos,
            encryptedContentInfo,
        })
        const asn1 = envelopedData.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        const valueBlock = asn1.valueBlock as any
        expect(valueBlock.value).toHaveLength(3)
        expect(valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)
    })

    it('should convert to string', () => {
        const recipientInfos: any[] = []
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const envelopedData = new EnvelopedData({
            version: 0,
            recipientInfos,
            encryptedContentInfo,
        })
        const str = envelopedData.toString()

        expect(typeof str).toEqual('string')
        expect(str).toContain('[EnvelopedData] SEQUENCE')
    })

    it('should parse from ASN.1 structure', () => {
        const recipientInfos: any[] = []
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const originalEnvelopedData = new EnvelopedData({
            version: 0,
            recipientInfos,
            encryptedContentInfo,
        })

        const asn1 = originalEnvelopedData.toAsn1()
        const parsedEnvelopedData = EnvelopedData.fromAsn1(asn1)

        expect(parsedEnvelopedData.version).toEqual(
            originalEnvelopedData.version,
        )
        expect(parsedEnvelopedData.recipientInfos.length).toEqual(
            originalEnvelopedData.recipientInfos.length,
        )
        expect(parsedEnvelopedData.encryptedContentInfo.contentType).toEqual(
            originalEnvelopedData.encryptedContentInfo.contentType,
        )

        // Compare encrypted content
        expect(
            parsedEnvelopedData.encryptedContentInfo.encryptedContent,
        ).toEqual(originalEnvelopedData.encryptedContentInfo.encryptedContent)
    })

    it('EnvelopedData toString snapshot', () => {
        const recipientInfos: any[] = []
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const obj = new EnvelopedData({
            version: 0,
            recipientInfos,
            encryptedContentInfo,
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[EnvelopedData] SEQUENCE :
            INTEGER : 0
            SET :
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              SEQUENCE :
                OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
              OCTET STRING : 0102030405"
        `)
    })

    it('EnvelopedData toPem snapshot', () => {
        const recipientInfos: any[] = []
        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            encryptedContent: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const obj = new EnvelopedData({
            version: 0,
            recipientInfos,
            encryptedContentInfo,
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ENVELOPEDDATA-----
          MCYCAQAxADAfBgkqhkiG9w0BBwEwCwYJKoZIhvcNAQEBgAUBAgMEBQ==
          -----END ENVELOPEDDATA-----"
        `)
    })
})
