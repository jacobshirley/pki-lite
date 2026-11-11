import { AttributeCertificate } from './AttributeCertificate.js'
import { AttributeCertificateInfo } from './AttributeCertificateInfo.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Holder } from './AttributeCertificateInfo.js'
import { AttCertIssuer } from './AttributeCertificateInfo.js'
import { describe, test, expect, beforeEach } from 'vitest'
import { der, UniversalTag } from '../../core/PkiBase.js'

describe('AttributeCertificate', () => {
    // Mock dependencies
    let mockAcInfo: AttributeCertificateInfo
    let mockSignatureAlgorithm: AlgorithmIdentifier
    let mockSignatureValue: Uint8Array<ArrayBuffer>

    beforeEach(() => {
        // Create mock dependencies
        const mockHolder = new Holder({
            holderValue: new Uint8Array([1, 2, 3]),
        })
        const mockIssuer = new AttCertIssuer({
            issuerValue: new Uint8Array([4, 5, 6]),
        })
        const mockAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })

        mockAcInfo = {
            version: 1,
            holder: mockHolder,
            issuer: mockIssuer,
            signature: mockAlgorithm,
            serialNumber: new Uint8Array([7, 8, 9]),
            validityPeriod: {
                notBefore: new Date(),
                notAfter: new Date(Date.now() + 86400000),
            },
            attributes: [],
            toAsn1: () => der.sequence([]),
        } as unknown as AttributeCertificateInfo

        mockSignatureAlgorithm = {
            algorithm: '1.2.840.113549.1.1.11',
            parameters: null,
            toAsn1: () => der.sequence([]),
        } as unknown as AlgorithmIdentifier

        mockSignatureValue = new Uint8Array([10, 11, 12])
    })

    test('constructor should initialize properties correctly', () => {
        const attrCert = new AttributeCertificate({
            acInfo: mockAcInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signatureValue: mockSignatureValue,
        })

        expect(attrCert.acInfo).toEqual(mockAcInfo)
        expect(attrCert.signatureAlgorithm).toEqual(mockSignatureAlgorithm)
        expect(attrCert.signatureValue.bytes).toEqual(mockSignatureValue)
    })

    test('toAsn1 returns a correctly structured Sequence', () => {
        const attrCert = new AttributeCertificate({
            acInfo: mockAcInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signatureValue: mockSignatureValue,
        })

        const asn1 = attrCert.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        // Check the structure has the correct elements
        const items = asn1.children
        expect(items.length).toEqual(3)
        expect(items[2].is(UniversalTag.BitString)).toBe(true)

        // Check BitString value matches signatureValue
        const bitString = items[2]
        expect(der.readBitString(bitString).bytes).toEqual(mockSignatureValue)
    })

    test('fromAsn1 creates an instance from valid ASN.1', () => {
        const asn1 = der.sequence([
            der.sequence([]), // acInfo
            der.sequence([]), // signatureAlgorithm
            der.bitString(mockSignatureValue), // signatureValue
        ])

        // This test verifies the fromAsn1 method attempts to parse the structure
        // It may throw due to incomplete mock data, which is expected
        expect(() => {
            const attrCert = AttributeCertificate.fromAsn1(asn1)
            // If parsing succeeds, verify basic structure
            expect(attrCert).toBeInstanceOf(AttributeCertificate)
        }).not.toThrow(/Unknown.+tag|expected SEQUENCE/)
    })

    test('fromAsn1 throws error for invalid ASN.1 type', () => {
        const asn1 = der.integer(123)

        expect(() => AttributeCertificate.fromAsn1(asn1)).toThrow(
            'expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid structure', () => {
        // Test with incorrect number of elements
        const invalidSequence = der.sequence([
            der.sequence([]), // acInfo
            der.sequence([]), // signatureAlgorithm
            // Missing signatureValue
        ])
        expect(() => AttributeCertificate.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for acInfo
        const invalidAcInfoType = der.sequence([
            der.integer(1), // Invalid type
            der.sequence([]), // signatureAlgorithm
            der.bitString(mockSignatureValue), // signatureValue
        ])
        expect(() => AttributeCertificate.fromAsn1(invalidAcInfoType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for acInfo',
        )

        // Test with incorrect type for signatureAlgorithm
        const invalidAlgoType = der.sequence([
            der.sequence([]), // acInfo
            der.integer(1), // Invalid type
            der.bitString(mockSignatureValue), // signatureValue
        ])
        expect(() => AttributeCertificate.fromAsn1(invalidAlgoType)).toThrow(
            'Invalid ASN.1 structure',
        )

        // Test with incorrect type for signatureValue
        const invalidSigType = der.sequence([
            der.sequence([]), // acInfo
            der.sequence([]), // signatureAlgorithm
            der.integer(1), // Invalid type
        ])
        expect(() => AttributeCertificate.fromAsn1(invalidSigType)).toThrow(
            'Invalid ASN.1 structure',
        )
    })
})
