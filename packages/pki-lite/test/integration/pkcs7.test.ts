import { describe, it, expect, beforeEach, assert } from 'vitest'
import { AlgorithmIdentifier } from '../../src/algorithms/AlgorithmIdentifier.js'
import { Name } from '../../src/x509/Name.js'
import { RelativeDistinguishedName } from '../../src/x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../../src/x509/AttributeTypeAndValue.js'
import { IssuerAndSerialNumber } from '../../src/pkcs7/IssuerAndSerialNumber.js'
import { EncapsulatedContentInfo } from '../../src/pkcs7/EncapsulatedContentInfo.js'
import { SignerInfo } from '../../src/pkcs7/SignerInfo.js'
import { SignedData } from '../../src/pkcs7/SignedData.js'
import { asn1js } from '../../src/core/PkiBase.js'
import { DigestedData } from '../../src/pkcs7/DigestedData.js'
import { RecipientInfo } from '../../src/pkcs7/recipients/RecipientInfo.js'
import { EnvelopedData } from '../../src/pkcs7/EnvelopedData.js'
import { EncryptedData } from '../../src/pkcs7/EncryptedData.js'
import { OIDs } from '../../src/core/OIDs.js'
import { EncryptedContentInfo } from '../../src/pkcs7/EncryptedContentInfo.js'

describe('PKCS#7 Integration Tests', () => {
    let issuer: Name
    let issuerAndSerialNumber: IssuerAndSerialNumber

    beforeEach(() => {
        issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
                new AttributeTypeAndValue({ type: '2.5.4.6', value: 'US' }),
            ),
        )
        issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer,
            serialNumber: 123456789,
        })
    })

    it('should create a complete SignedData structure', () => {
        // Create data to sign
        const dataContent = new TextEncoder().encode('Hello, PKCS#7 World!')
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: dataContent,
        })

        // Create digest algorithms
        const sha256 = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const digestAlgorithms = [sha256]

        // Create signer info
        const digestEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const encryptedDigest = new Uint8Array(256) // Mock signature
        for (let i = 0; i < encryptedDigest.length; i++) {
            encryptedDigest[i] = i % 256
        }

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm: sha256,
            signatureAlgorithm: digestEncryptionAlgorithm,
            signature: encryptedDigest,
        })

        const signerInfos = [signerInfo]

        // Create SignedData
        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: contentInfo,
            signerInfos: signerInfos,
        })

        // Verify the structure
        expect(signedData.version).toBe(1)
        expect(signedData.digestAlgorithms.length).toBe(1)
        expect(signedData.encapContentInfo.eContentType.toString()).toBe(
            OIDs.PKCS7.DATA,
        )
        expect(signedData.signerInfos.length).toBe(1)

        // Convert to ASN.1 and verify it's a valid structure
        const asn1 = signedData.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(4) // version, digestAlgorithms, contentInfo, signerInfos
    })

    it('should create a EncapsulatedContentInfo wrapper for SignedData', () => {
        // Create minimal SignedData
        const dataContent = new TextEncoder().encode('Test data')
        const innerContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: dataContent,
        })

        const digestAlgorithms = [
            new AlgorithmIdentifier({ algorithm: '2.16.840.1.101.3.4.2.1' }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.2.1',
            }),
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            signature: new Uint8Array([1, 2, 3, 4, 5]),
        })

        const signedData = new SignedData({
            version: 1,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: innerContentInfo,
            signerInfos: [signerInfo],
        })

        // Wrap SignedData in EncapsulatedContentInfo
        const outerContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.SIGNED_DATA,
            eContent: signedData.toDer(),
        })

        expect(outerContentInfo.eContentType.toString()).toBe(
            OIDs.PKCS7.SIGNED_DATA,
        )
        expect(outerContentInfo.eContent).toEqual(signedData.toDer())

        const asn1 = outerContentInfo.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2) // contentType + content
    })

    it('should create a DigestedData structure', () => {
        const dataContent = new TextEncoder().encode('Data to digest')
        const contentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: dataContent,
        })

        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const digest = new Uint8Array(32) // SHA-256 produces 32 bytes
        for (let i = 0; i < digest.length; i++) {
            digest[i] = i
        }

        const digestedData = new DigestedData({
            version: 1,
            digestAlgorithm: digestAlgorithm,
            encapContentInfo: contentInfo,
            digest: digest,
        })

        expect(digestedData.version).toBe(1)
        expect(digestedData.digestAlgorithm.algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.1',
        )
        expect(digestedData.encapContentInfo).toBe(contentInfo)
        expect(digestedData.digest.length).toBe(32)

        const asn1 = digestedData.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(4) // version, digestAlgorithm, contentInfo, digest
    })

    it('should create an EnvelopedData structure', () => {
        // Create recipient info
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const encryptedKey = new Uint8Array(256) // RSA-2048 encrypted key
        for (let i = 0; i < encryptedKey.length; i++) {
            encryptedKey[i] = (i * 7) % 256
        }

        const recipientInfo = new RecipientInfo.KeyTransRecipientInfo({
            version: 1,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        const recipientInfos = [recipientInfo]

        // Create encrypted content info
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        }) // AES-128-CBC
        const encryptedContent = new Uint8Array(48) // Some encrypted content
        for (let i = 0; i < encryptedContent.length; i++) {
            encryptedContent[i] = (i * 13) % 256
        }

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            encryptedContent: encryptedContent,
        })

        // Create EnvelopedData
        const envelopedData = new EnvelopedData({
            version: 1,
            recipientInfos: recipientInfos,
            encryptedContentInfo: encryptedContentInfo,
        })

        expect(envelopedData.version).toBe(1)
        expect(envelopedData.recipientInfos.length).toBe(1)
        expect(envelopedData.encryptedContentInfo).toBe(encryptedContentInfo)

        const asn1 = envelopedData.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3) // version, recipientInfos, encryptedContentInfo
    })

    it('should create an EncryptedData structure', () => {
        const contentEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.2',
        }) // AES-128-CBC
        const encryptedContent = new Uint8Array(64)
        for (let i = 0; i < encryptedContent.length; i++) {
            encryptedContent[i] = (i * 17) % 256
        }

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: OIDs.PKCS7.DATA,
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            encryptedContent: encryptedContent,
        })

        const encryptedData = new EncryptedData({
            version: 1,
            encryptedContentInfo: encryptedContentInfo,
        })

        expect(encryptedData.version).toBe(1)
        expect(encryptedData.encryptedContentInfo).toBe(encryptedContentInfo)

        const asn1 = encryptedData.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2) // version, encryptedContentInfo
    })

    it('should handle nested EncapsulatedContentInfo structures', () => {
        // Create inner data
        const innerData = new TextEncoder().encode('Nested content')
        const innerContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DATA,
            eContent: innerData,
        })

        // Create DigestedData containing the inner content
        const digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const digest = new Uint8Array(32)
        const digestedData = new DigestedData({
            version: 1,
            digestAlgorithm: digestAlgorithm,
            encapContentInfo: innerContentInfo,
            digest: digest,
        })

        // Wrap DigestedData in outer EncapsulatedContentInfo
        const outerContentInfo = new EncapsulatedContentInfo({
            eContentType: OIDs.PKCS7.DIGESTED_DATA,
            eContent: digestedData.toDer(),
        })

        expect(outerContentInfo.eContentType.toString()).toBe(
            OIDs.PKCS7.DIGESTED_DATA,
        )
        expect(outerContentInfo.eContent).toEqual(digestedData.toDer())

        const asn1 = outerContentInfo.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
    })
})
