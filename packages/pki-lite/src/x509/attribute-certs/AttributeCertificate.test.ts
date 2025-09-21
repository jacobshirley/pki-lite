import * as asn1js from 'asn1js'
import { AttributeCertificate } from './AttributeCertificate.js'
import { AttributeCertificateInfo } from './AttributeCertificateInfo.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Holder } from './AttributeCertificateInfo.js'
import { AttCertIssuer } from './AttributeCertificateInfo.js'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('AttributeCertificate', () => {
    // Mock dependencies
    let mockAcInfo: AttributeCertificateInfo
    let mockSignatureAlgorithm: AlgorithmIdentifier
    let mockSignatureValue: Uint8Array

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
            toAsn1: vi.fn().mockReturnValue(new asn1js.Sequence({ value: [] })),
        } as unknown as AttributeCertificateInfo

        mockSignatureAlgorithm = {
            algorithm: '1.2.840.113549.1.1.11',
            parameters: null,
            toAsn1: vi.fn().mockReturnValue(new asn1js.Sequence({ value: [] })),
        } as unknown as AlgorithmIdentifier

        mockSignatureValue = new Uint8Array([10, 11, 12])

        // Setup mocks for fromAsn1 methods
        vi.spyOn(AttributeCertificateInfo, 'fromAsn1').mockReturnValue(
            mockAcInfo,
        )
        vi.spyOn(AlgorithmIdentifier, 'fromAsn1').mockReturnValue(
            mockSignatureAlgorithm,
        )
    })

    afterEach(() => {
        vi.restoreAllMocks()
    })

    test('constructor should initialize properties correctly', () => {
        const attrCert = new AttributeCertificate({
            acInfo: mockAcInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signatureValue: mockSignatureValue,
        })

        expect(attrCert.acInfo).toBe(mockAcInfo)
        expect(attrCert.signatureAlgorithm).toBe(mockSignatureAlgorithm)
        expect(attrCert.signatureValue.bytes).toBe(mockSignatureValue)
    })

    test('toAsn1 returns a correctly structured Sequence', () => {
        const attrCert = new AttributeCertificate({
            acInfo: mockAcInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signatureValue: mockSignatureValue,
        })

        const asn1 = attrCert.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(mockAcInfo.toAsn1).toHaveBeenCalled()
        expect(mockSignatureAlgorithm.toAsn1).toHaveBeenCalled()

        // Check the structure has the correct elements
        const valueBlock = (asn1 as asn1js.Sequence).valueBlock
        expect(valueBlock.value.length).toBe(3)
        expect(valueBlock.value[2]).toBeInstanceOf(asn1js.BitString)

        // Check BitString value matches signatureValue
        const bitString = valueBlock.value[2] as asn1js.BitString
        expect(new Uint8Array(bitString.valueBlock.valueHexView)).toEqual(
            mockSignatureValue,
        )
    })

    test('fromAsn1 creates an instance from valid ASN.1', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // acInfo
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.BitString({ valueHex: mockSignatureValue }), // signatureValue
            ],
        })

        const attrCert = AttributeCertificate.fromAsn1(asn1)

        expect(AttributeCertificateInfo.fromAsn1).toHaveBeenCalledWith(
            asn1.valueBlock.value[0],
        )
        expect(AlgorithmIdentifier.fromAsn1).toHaveBeenCalledWith(
            asn1.valueBlock.value[1],
        )
        expect(attrCert.acInfo).toBe(mockAcInfo)
        expect(attrCert.signatureAlgorithm).toBe(mockSignatureAlgorithm)
        expect(attrCert.signatureValue.bytes).toEqual(mockSignatureValue)
    })

    test('fromAsn1 throws error for invalid ASN.1 type', () => {
        const asn1 = new asn1js.Integer({ value: 123 })

        expect(() => AttributeCertificate.fromAsn1(asn1)).toThrow(
            'expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid structure', () => {
        // Test with incorrect number of elements
        const invalidSequence = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // acInfo
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                // Missing signatureValue
            ],
        })
        expect(() => AttributeCertificate.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for acInfo
        const invalidAcInfoType = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // Invalid type
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.BitString({ valueHex: mockSignatureValue }), // signatureValue
            ],
        })
        expect(() => AttributeCertificate.fromAsn1(invalidAcInfoType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for acInfo',
        )

        // Test with incorrect type for signatureAlgorithm
        const invalidAlgoType = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // acInfo
                new asn1js.Integer({ value: 1 }), // Invalid type
                new asn1js.BitString({ valueHex: mockSignatureValue }), // signatureValue
            ],
        })
        expect(() => AttributeCertificate.fromAsn1(invalidAlgoType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
        )

        // Test with incorrect type for signatureValue
        const invalidSigType = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // acInfo
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.Integer({ value: 1 }), // Invalid type
            ],
        })
        expect(() => AttributeCertificate.fromAsn1(invalidSigType)).toThrow(
            'Invalid ASN.1 structure: expected BIT STRING for signatureValue',
        )
    })
})
