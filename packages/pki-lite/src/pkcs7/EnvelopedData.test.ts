import { describe, it, expect } from 'vitest'
import { EnvelopedData } from './EnvelopedData.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { der, derToAsn1, UniversalTag } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { Attribute } from '../x509/Attribute.js'

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

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)
        const items = asn1.children
        expect(items).toHaveLength(3)
        expect(items[0].is(UniversalTag.Integer)).toBe(true)
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
              [0] : 0102030405"
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

    it('keeps all unprotectedAttrs through a DER round trip ([1] IMPLICIT SET OF)', () => {
        const attr = (oid: string, value: number) =>
            new Attribute({
                type: oid,
                values: [der.integer(value)],
            })
        const original = new EnvelopedData({
            version: 0,
            recipientInfos: [],
            encryptedContentInfo: new EncryptedContentInfo({
                contentType: OIDs.PKCS7.DATA,
                contentEncryptionAlgorithm: new AlgorithmIdentifier({
                    algorithm: '1.2.840.113549.1.1.1',
                }),
                encryptedContent: new Uint8Array([1, 2, 3]),
            }),
            unprotectedAttrs: [attr('1.2.3.4', 1), attr('1.2.3.5', 2)],
        })

        const encoded = original.toDer()
        const parsed = EnvelopedData.fromAsn1(derToAsn1(encoded))

        expect(parsed.unprotectedAttrs).toHaveLength(2)
        expect(parsed.toDer()).toEqual(encoded)
    })

    it('rejects trailing elements instead of silently dropping them (e.g. AuthEnvelopedData)', () => {
        const valid = new EnvelopedData({
            version: 0,
            recipientInfos: [],
            encryptedContentInfo: new EncryptedContentInfo({
                contentType: OIDs.PKCS7.DATA,
                contentEncryptionAlgorithm: new AlgorithmIdentifier({
                    algorithm: '1.2.840.113549.1.1.1',
                }),
                encryptedContent: new Uint8Array([1, 2, 3]),
            }),
        }).toAsn1()
        // AuthEnvelopedData carries a `mac OCTET STRING` after the content info
        const withMac = der.sequence([
            ...valid.children,
            der.octetString(new Uint8Array([9, 9])),
        ])

        expect(() => EnvelopedData.fromAsn1(withMac)).toThrow(
            /AuthEnvelopedData/,
        )
    })
})
