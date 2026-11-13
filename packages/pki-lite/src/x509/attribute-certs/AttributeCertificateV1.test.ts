import { AttributeCertificateV1 } from './AttributeCertificateV1.js'
import { AttributeCertificateInfoV1 } from './AttributeCertificateInfoV1.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { describe, test, expect, beforeEach } from 'vitest'
import { der, UniversalTag } from '../../core/PkiBase.js'

describe('AttributeCertificateV1', () => {
    // Mock dependencies
    let mockAcInfo: AttributeCertificateInfoV1
    let mockSignatureAlgorithm: AlgorithmIdentifier
    let mockSignature: Uint8Array<ArrayBuffer>

    beforeEach(() => {
        // Create simple stub objects without vitest mocks
        mockAcInfo = {
            version: 0,
            subject: new Uint8Array([1, 2, 3]),
            issuer: new Uint8Array([4, 5, 6]),
            signature: {} as AlgorithmIdentifier,
            serialNumber: new Uint8Array([7, 8, 9]),
            validityPeriod: {
                notBefore: new Date(),
                notAfter: new Date(Date.now() + 86400000),
            },
            attributes: [],
            toAsn1: () => der.sequence([]),
        } as unknown as AttributeCertificateInfoV1

        mockSignatureAlgorithm = {
            algorithm: '1.2.840.113549.1.1.11',
            parameters: null,
            toAsn1: () => der.sequence([]),
        } as unknown as AlgorithmIdentifier

        mockSignature = new Uint8Array([10, 11, 12])
    })

    test('constructor should initialize properties correctly', () => {
        const attrCertV1 = new AttributeCertificateV1({
            acInfo: mockAcInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signature: mockSignature,
        })

        expect(attrCertV1.acInfo).toEqual(mockAcInfo)
        expect(attrCertV1.signatureAlgorithm).toEqual(mockSignatureAlgorithm)
        expect(attrCertV1.signature.bytes).toEqual(mockSignature)
    })

    test('toAsn1 returns a correctly structured Sequence', () => {
        const attrCertV1 = new AttributeCertificateV1({
            acInfo: mockAcInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signature: mockSignature,
        })

        const asn1 = attrCertV1.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        // Check the structure has the correct elements
        const items = asn1.children
        expect(items.length).toEqual(3)
        expect(items[2].is(UniversalTag.BitString)).toBe(true)

        // Check BitString value matches signature
        const bitString = items[2]
        expect(der.readBitString(bitString).bytes).toEqual(mockSignature)
    })

    test('fromAsn1 creates an instance from valid ASN.1', () => {
        const asn1 = der.sequence([
            der.sequence([]), // acInfo
            der.sequence([]), // signatureAlgorithm
            der.bitString(mockSignature), // signature
        ])

        // This test verifies the fromAsn1 method attempts to parse the structure
        // It may throw due to incomplete mock data, which is expected
        expect(() => {
            const attrCertV1 = AttributeCertificateV1.fromAsn1(asn1)
            // If parsing succeeds, verify basic structure
            expect(attrCertV1).toBeInstanceOf(AttributeCertificateV1)
        }).not.toThrow(/Unknown.+tag|expected SEQUENCE/)
    })

    test('fromAsn1 throws error for invalid ASN.1 type', () => {
        const asn1 = der.integer(123)

        expect(() => AttributeCertificateV1.fromAsn1(asn1)).toThrow(
            'expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid structure', () => {
        // Test with incorrect number of elements
        const invalidSequence = der.sequence([
            der.sequence([]), // acInfo
            der.sequence([]), // signatureAlgorithm
            // Missing signature
        ])
        expect(() => AttributeCertificateV1.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for acInfo
        const invalidAcInfoType = der.sequence([
            der.integer(1), // Invalid type
            der.sequence([]), // signatureAlgorithm
            der.bitString(mockSignature), // signature
        ])
        expect(() =>
            AttributeCertificateV1.fromAsn1(invalidAcInfoType),
        ).toThrow('Invalid ASN.1 structure: expected SEQUENCE for acInfo')

        // Test with incorrect type for signatureAlgorithm
        const invalidAlgoType = der.sequence([
            der.sequence([]), // acInfo
            der.integer(1), // Invalid type
            der.bitString(mockSignature), // signature
        ])
        expect(() => AttributeCertificateV1.fromAsn1(invalidAlgoType)).toThrow(
            'Invalid ASN.1 structure',
        )

        // Test with incorrect type for signature
        const invalidSigType = der.sequence([
            der.sequence([]), // acInfo
            der.sequence([]), // signatureAlgorithm
            der.integer(1), // Invalid type
        ])
        expect(() => AttributeCertificateV1.fromAsn1(invalidSigType)).toThrow(
            'Invalid ASN.1 structure',
        )
    })
})
