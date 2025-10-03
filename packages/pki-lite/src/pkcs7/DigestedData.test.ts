import { describe, it, expect, assert } from 'vitest'
import { DigestedData } from './DigestedData.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'
import { asn1js } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'

describe('DigestedData', () => {
    it('should create DigestedData', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: new Uint8Array([1, 2, 3, 4]),
        })
        const digest = new Uint8Array([5, 6, 7, 8])

        const digestedData = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })

        expect(digestedData.version).toEqual(1)
        expect(digestedData.digestAlgorithm).toEqual(digestAlgorithm)
        expect(digestedData.encapContentInfo).toEqual(contentInfo)
        expect(digestedData.digest).toEqual(digest)
    })

    it('should convert to ASN.1 structure', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: new Uint8Array([1, 2, 3, 4]),
        })
        const digest = new Uint8Array([5, 6, 7, 8])

        const digestedData = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })
        const asn1 = digestedData.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value).toHaveLength(4) // version, digestAlgorithm, contentInfo, digest
    })

    it('should convert to string', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })
        const digest = new Uint8Array([5, 6, 7, 8])

        const digestedData = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })
        const str = digestedData.toString()

        expect(typeof str).toEqual('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('DigestedData toString snapshot', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: '123',
        })
        const digest = new Uint8Array([1, 2, 3, 4, 5])
        const obj = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[DigestedData] SEQUENCE :
            INTEGER : 1
            SEQUENCE :
              OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              [0] :
                OCTET STRING : 313233
            OCTET STRING : 0102030405"
        `)
    })

    it('DigestedData toPem snapshot', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
        })
        const digest = new Uint8Array([1, 2, 3, 4, 5])
        const obj = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN DIGESTEDDATA-----
          MCQCAQEwCwYJYIZIAWUDBAIBMAsGCSqGSIb3DQEHAQQFAQIDBAU=
          -----END DIGESTEDDATA-----"
        `)
    })

    it('DigestedData toString snapshot with content', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: new Uint8Array([1, 2, 3, 4]),
        })
        const digest = new Uint8Array([5, 6, 7, 8])
        const obj = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[DigestedData] SEQUENCE :
            INTEGER : 1
            SEQUENCE :
              OBJECT IDENTIFIER : 2.16.840.1.101.3.4.2.1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.7.1
              [0] :
                OCTET STRING : 01020304
            OCTET STRING : 05060708"
        `)
    })

    it('DigestedData toPem snapshot with content', () => {
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: new Uint8Array([1, 2, 3, 4]),
        })
        const digest = new Uint8Array([5, 6, 7, 8])
        const obj = new DigestedData({
            version: 1,
            digestAlgorithm,
            encapContentInfo: contentInfo,
            digest,
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN DIGESTEDDATA-----
          MCsCAQEwCwYJYIZIAWUDBAIBMBMGCSqGSIb3DQEHAaAGBAQBAgMEBAQFBgcI
          -----END DIGESTEDDATA-----"
        `)
    })
})
