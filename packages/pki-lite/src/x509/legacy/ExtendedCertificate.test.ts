import * as asn1js from 'asn1js'
import { ExtendedCertificate } from './ExtendedCertificate.js'
import { ExtendedCertificateInfo } from './ExtendedCertificateInfo.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../Certificate.js'
import { Attribute } from '../Attribute.js'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { BitString } from '../../asn1/BitString.js'

describe('ExtendedCertificate', () => {
    // Mock dependencies
    let mockExtendedCertificateInfo: ExtendedCertificateInfo
    let mockSignatureAlgorithm: AlgorithmIdentifier
    let mockSignature: BitString

    beforeEach(() => {
        // Set up mocks
        const mockCertificate = {} as Certificate
        const mockAttributes: Attribute[] = []

        mockExtendedCertificateInfo = {
            version: 1,
            certificate: mockCertificate,
            attributes: mockAttributes,
            toAsn1: vi.fn().mockReturnValue(new asn1js.Sequence({ value: [] })),
        } as unknown as ExtendedCertificateInfo

        mockSignatureAlgorithm = {
            algorithm: '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
            parameters: null,
            toAsn1: vi.fn().mockReturnValue(new asn1js.Sequence({ value: [] })),
        } as unknown as AlgorithmIdentifier

        mockSignature = new BitString({ value: new Uint8Array([1, 2, 3, 4]) })

        // Setup mocks for fromAsn1 methods
        vi.spyOn(ExtendedCertificateInfo, 'fromAsn1').mockReturnValue(
            mockExtendedCertificateInfo,
        )
        vi.spyOn(AlgorithmIdentifier, 'fromAsn1').mockReturnValue(
            mockSignatureAlgorithm,
        )
    })

    afterEach(() => {
        vi.restoreAllMocks()
    })

    test('constructor should initialize properties correctly', () => {
        const extCert = new ExtendedCertificate({
            extendedCertificateInfo: mockExtendedCertificateInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signature: mockSignature,
        })

        expect(extCert.extendedCertificateInfo).toBe(
            mockExtendedCertificateInfo,
        )
        expect(extCert.signatureAlgorithm).toBe(mockSignatureAlgorithm)
        expect(extCert.signature).toEqual(mockSignature)
    })

    test('toAsn1 should return correct ASN.1 structure', () => {
        const extCert = new ExtendedCertificate({
            extendedCertificateInfo: mockExtendedCertificateInfo,
            signatureAlgorithm: mockSignatureAlgorithm,
            signature: mockSignature,
        })

        const asn1 = extCert.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(mockExtendedCertificateInfo.toAsn1).toHaveBeenCalled()
        expect(mockSignatureAlgorithm.toAsn1).toHaveBeenCalled()

        // Check that BitString was created with correct value
        const valueBlock = (asn1 as asn1js.Sequence).valueBlock
        expect(valueBlock.value.length).toBe(3)
        expect(valueBlock.value[2]).toBeInstanceOf(asn1js.BitString)

        // Check BitString value matches signature
        const bitString = valueBlock.value[2] as asn1js.BitString
        expect(new Uint8Array(bitString.valueBlock.valueHexView)).toEqual(
            mockSignature.bytes,
        )
    })

    test('fromAsn1 should parse ASN.1 structure correctly', () => {
        // Create mock ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // extendedCertificateInfo
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.BitString({ valueHex: mockSignature.bytes }), // signature
            ],
        })

        const extCert = ExtendedCertificate.fromAsn1(asn1)

        expect(ExtendedCertificateInfo.fromAsn1).toHaveBeenCalledWith(
            asn1.valueBlock.value[0],
        )
        expect(AlgorithmIdentifier.fromAsn1).toHaveBeenCalledWith(
            asn1.valueBlock.value[1],
        )
        expect(extCert.extendedCertificateInfo).toBe(
            mockExtendedCertificateInfo,
        )
        expect(extCert.signatureAlgorithm).toBe(mockSignatureAlgorithm)
        expect(extCert.signature).toEqual(mockSignature)
    })

    test('fromAsn1 throws error for invalid ASN.1 type', () => {
        const asn1 = new asn1js.Integer({ value: 123 })

        expect(() => ExtendedCertificate.fromAsn1(asn1)).toThrow(
            'expected SEQUENCE',
        )
    })

    test('fromAsn1 should throw error for ASN.1 structure with incorrect elements', () => {
        // Test with incorrect number of elements
        const invalidSequence = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // extendedCertificateInfo
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                // Missing signature
            ],
        })
        expect(() => ExtendedCertificate.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for extendedCertificateInfo
        const invalidInfoType = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // Invalid type
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.BitString({ valueHex: mockSignature.bytes }), // signature
            ],
        })
        expect(() => ExtendedCertificate.fromAsn1(invalidInfoType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for extendedCertificateInfo',
        )

        // Test with incorrect type for signatureAlgorithm
        const invalidAlgoType = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // extendedCertificateInfo
                new asn1js.Integer({ value: 1 }), // Invalid type
                new asn1js.BitString({ valueHex: mockSignature.bytes }), // signature
            ],
        })
        expect(() => ExtendedCertificate.fromAsn1(invalidAlgoType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
        )

        // Test with incorrect type for signature
        const invalidSigType = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // extendedCertificateInfo
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.Integer({ value: 1 }), // Invalid type
            ],
        })
        expect(() => ExtendedCertificate.fromAsn1(invalidSigType)).toThrow(
            'Invalid ASN.1 structure: expected BIT STRING for signature',
        )
    })
})
