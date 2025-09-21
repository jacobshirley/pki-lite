import { describe, it, expect, assert } from 'vitest'
import { EncryptedData } from './EncryptedData.js'
import {
    AlgorithmIdentifier,
    ContentEncryptionAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { OctetString } from '../asn1/OctetString.js'

describe('EncryptedContentInfo', () => {
    it('should create EncryptedContentInfo without encrypted content', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm =
            new ContentEncryptionAlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.1.2',
            }) // AES-128-CBC

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
        })

        expect(encryptedContentInfo.contentType.toString()).toEqual(contentType)
        expect(encryptedContentInfo.contentEncryptionAlgorithm).toEqual(
            contentEncryptionAlgorithm,
        )
        expect(encryptedContentInfo.encryptedContent).toBeUndefined()
    })

    it('should create EncryptedContentInfo with encrypted content', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        })
        const encryptedContent = new Uint8Array([1, 2, 3, 4, 5])

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
            encryptedContent,
        })

        expect(encryptedContentInfo.encryptedContent).toEqual(
            new OctetString({ bytes: encryptedContent }),
        )
    })

    it('should convert to ASN.1 structure without encrypted content', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        })

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
        })

        const asn1 = encryptedContentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value).toHaveLength(2) // contentType, contentEncryptionAlgorithm
    })

    it('should convert to ASN.1 structure with encrypted content', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        })
        const encryptedContent = new Uint8Array([1, 2, 3, 4, 5])

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
            encryptedContent,
        })

        const asn1 = encryptedContentInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value).toHaveLength(3) // includes encrypted content
    })

    it('should convert to string', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        })

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
        })

        const str = encryptedContentInfo.toString()

        expect(typeof str).toBe('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('should parse from ASN.1 structure without encrypted content', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        })

        const originalEncryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
        })

        const asn1 = originalEncryptedContentInfo.toAsn1()
        const parsedEncryptedContentInfo = EncryptedContentInfo.fromAsn1(asn1)

        expect(parsedEncryptedContentInfo.contentType).toEqual(
            originalEncryptedContentInfo.contentType,
        )
        expect(
            parsedEncryptedContentInfo.contentEncryptionAlgorithm.algorithm,
        ).toEqual(
            originalEncryptedContentInfo.contentEncryptionAlgorithm.algorithm,
        )
        expect(parsedEncryptedContentInfo.encryptedContent).toBeUndefined()
    })

    it('should parse from ASN.1 structure with encrypted content', () => {
        const contentType = OIDs.PKCS7.DATA
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        })
        const encryptedContent = new Uint8Array([1, 2, 3, 4, 5])

        const originalEncryptedContentInfo = new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
            encryptedContent,
        })

        const asn1 = originalEncryptedContentInfo.toAsn1()
        const parsedEncryptedContentInfo = EncryptedContentInfo.fromAsn1(asn1)

        expect(parsedEncryptedContentInfo.contentType).toEqual(
            originalEncryptedContentInfo.contentType,
        )
        expect(
            parsedEncryptedContentInfo.contentEncryptionAlgorithm.algorithm,
        ).toEqual(
            originalEncryptedContentInfo.contentEncryptionAlgorithm.algorithm,
        )
    })
})
