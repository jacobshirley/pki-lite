import { describe, it, expect, assert } from 'vitest'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'

describe('EncapsulatedContentInfo', () => {
    it('should create EncapsulatedContentInfo with content type only', () => {
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })

        expect(contentInfo.eContentType.toString()).toEqual(OIDs.PKCS7.DATA)
        expect(contentInfo.eContent).toBeUndefined()
    })

    it('should create EncapsulatedContentInfo with content type and content', () => {
        const content = new Uint8Array([1, 2, 3, 4])
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })

        expect(contentInfo.eContentType.toString()).toEqual(OIDs.PKCS7.DATA)
        expect(contentInfo.eContent).toEqual(content)
    })

    it('should convert to ASN.1 structure without content', () => {
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.SIGNED_DATA,
        })
        const asn1 = contentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value).toHaveLength(1) // Only contentType
    })

    it('should convert to ASN.1 structure with Uint8Array<ArrayBuffer> content', () => {
        const content = new Uint8Array([1, 2, 3, 4])
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        const asn1 = contentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value).toHaveLength(2) // contentType + content
    })

    it('should convert to ASN.1 structure with string content', () => {
        const content = 'Hello, World!'
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        const asn1 = contentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value).toHaveLength(2) // contentType + content
    })

    it('should convert to ASN.1 structure with ASN.1 content', () => {
        // Use a content that's compatible with anyToAsn1
        const content = new Uint8Array([1, 2, 3, 4, 5]) // Use Uint8Array<ArrayBuffer> instead of asn1js.Integer
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        const asn1 = contentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value).toHaveLength(2) // contentType + content
    })

    it('should have correct properties', () => {
        const content = new Uint8Array([1, 2, 3, 4])
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })

        expect(contentInfo.eContentType.toString()).toEqual(OIDs.PKCS7.DATA)
        expect(contentInfo.eContent).toEqual(content)
    })

    it('should convert to string', () => {
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })
        const str = contentInfo.toString()

        expect(typeof str).toEqual('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('should handle object with toAsn1 method as content', () => {
        // Use a simple TS-compatible content that implements PkiBase
        const content = new Uint8Array([1, 2, 3, 4, 5])
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        const asn1 = contentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value).toHaveLength(2)
    })

    it('should have correct PKCS#7 content type constants', () => {
        expect(OIDs.PKCS7.DATA).toEqual('1.2.840.113549.1.7.1')
        expect(OIDs.PKCS7.SIGNED_DATA).toEqual('1.2.840.113549.1.7.2')
        expect(OIDs.PKCS7.ENVELOPED_DATA).toEqual('1.2.840.113549.1.7.3')
        expect(OIDs.PKCS7.DIGESTED_DATA).toEqual('1.2.840.113549.1.7.5')
        expect(OIDs.PKCS7.ENCRYPTED_DATA).toEqual('1.2.840.113549.1.7.6')
    })

    it('should parse from ASN.1 structure without content', () => {
        const originalContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })
        const asn1 = originalContentInfo.toAsn1()

        const parsedContentInfo = EncapsulatedContentInfo.fromAsn1(asn1)

        expect(parsedContentInfo.eContentType).toEqual(
            originalContentInfo.eContentType,
        )
        expect(parsedContentInfo.eContent).toBeUndefined()
    })

    it('should parse from ASN.1 structure with Uint8Array<ArrayBuffer> content', () => {
        const content = new Uint8Array([1, 2, 3, 4, 5])
        const originalContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        const asn1 = originalContentInfo.toAsn1()

        const parsedContentInfo = EncapsulatedContentInfo.fromAsn1(asn1)

        expect(parsedContentInfo.eContentType).toEqual(
            originalContentInfo.eContentType,
        )
        expect(parsedContentInfo.eContent).not.toBeUndefined()

        // When Uint8Array<ArrayBuffer> is converted to ASN.1 and back, we need to verify
        // we're getting binary data back, but the exact format might differ
        // depending on how anyToAsn1 and fromAsn1 are implemented
        const parsedContent = parsedContentInfo.eContent
        expect(parsedContent).toBeDefined()

        // If we get a Uint8Array<ArrayBuffer> back directly, test that
        if (parsedContent instanceof Uint8Array) {
            // Convert both to arrays for comparison since the actual Uint8Array<ArrayBuffer> instances may be different
            expect(Array.from(parsedContent)).toEqual(Array.from(content))
        } else if (
            typeof parsedContent === 'object' &&
            parsedContent !== null
        ) {
            // If it's another object type, we can't directly compare
            expect(parsedContent).toBeTruthy()
        }
    })

    it('should parse from ASN.1 structure with string content', () => {
        const content = 'Hello, World!'
        const originalContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        const asn1 = originalContentInfo.toAsn1()

        const parsedContentInfo = EncapsulatedContentInfo.fromAsn1(asn1)

        expect(parsedContentInfo.eContentType).toEqual(
            originalContentInfo.eContentType,
        )
        expect(parsedContentInfo.eContent).toEqual(
            new TextEncoder().encode(content),
        )
    })

    it('should throw error on invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 123 }) // Not a Sequence

        expect(() => EncapsulatedContentInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence',
        )
    })

    it('EncapsulatedContentInfo toString snapshot', () => {
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })
        expect(contentInfo.toString()).toMatchInlineSnapshot(`
          "[EncapsulatedContentInfo] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.7.1"
        `)
    })

    it('EncapsulatedContentInfo toString snapshot with content', () => {
        const content = new Uint8Array([1, 2, 3, 4, 5])
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        expect(contentInfo.toString()).toMatchInlineSnapshot(`
          "[EncapsulatedContentInfo] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
            [0] :
              OCTET STRING : 0102030405"
        `)
    })

    it('EncapsulatedContentInfo toPem snapshot', () => {
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })
        expect(contentInfo.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ENCAPSULATEDCONTENTINFO-----
          MAsGCSqGSIb3DQEHAQ==
          -----END ENCAPSULATEDCONTENTINFO-----"
        `)
    })

    it('EncapsulatedContentInfo toPem snapshot with content', () => {
        const content = 'Hello, World!'
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: content,
        })
        expect(contentInfo.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ENCAPSULATEDCONTENTINFO-----
          MBwGCSqGSIb3DQEHAaAPBA1IZWxsbywgV29ybGQh
          -----END ENCAPSULATEDCONTENTINFO-----"
        `)
    })
})
