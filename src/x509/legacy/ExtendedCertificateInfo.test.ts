import * as asn1js from 'asn1js'
import { ExtendedCertificateInfo } from './ExtendedCertificateInfo.js'
import { Certificate } from '../Certificate.js'
import { Attribute } from '../Attribute.js'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('ExtendedCertificateInfo', () => {
    // Mock dependencies
    let mockCertificate: Certificate
    let mockAttributes: Attribute[]

    beforeEach(() => {
        // Set up mocks
        mockCertificate = {
            toAsn1: vi.fn().mockReturnValue(new asn1js.Sequence({ value: [] })),
        } as unknown as Certificate

        mockAttributes = [
            {
                type: '1.2.3.4.5',
                values: ['test-attribute'],
                toAsn1: vi
                    .fn()
                    .mockReturnValue(new asn1js.Sequence({ value: [] })),
            } as unknown as Attribute,
        ]

        // Setup mocks for fromAsn1 methods
        vi.spyOn(Certificate, 'fromAsn1').mockReturnValue(mockCertificate)
        vi.spyOn(Attribute, 'fromAsn1').mockReturnValue(mockAttributes[0])
    })

    afterEach(() => {
        vi.restoreAllMocks()
    })

    test('constructor should initialize properties correctly', () => {
        const version = 1
        const info = new ExtendedCertificateInfo({
            version,
            certificate: mockCertificate,
            attributes: mockAttributes,
        })

        expect(info.version).toBe(version)
        expect(info.certificate).toBe(mockCertificate)
        expect(info.attributes).toEqual(mockAttributes)
    })

    test('toAsn1 should return correct ASN.1 structure', () => {
        const version = 1
        const info = new ExtendedCertificateInfo({
            version,
            certificate: mockCertificate,
            attributes: mockAttributes,
        })

        const asn1 = info.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(mockCertificate.toAsn1).toHaveBeenCalled()

        // Check that structure has correct elements
        const valueBlock = (asn1 as asn1js.Sequence).valueBlock
        expect(valueBlock.value.length).toBe(3)
        expect(valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)

        // Check version value is correct
        const versionAsn1 = valueBlock.value[0] as asn1js.Integer
        expect(versionAsn1.valueBlock.valueDec).toBe(version)

        // Check that attributes were converted to a Set
        expect(valueBlock.value[2]).toBeInstanceOf(asn1js.Set)

        // Check that each attribute's toAsn1 was called
        for (const attr of mockAttributes) {
            expect(attr.toAsn1).toHaveBeenCalled()
        }
    })

    test('fromAsn1 should parse ASN.1 structure correctly', () => {
        // Create mock ASN.1 structure
        const version = 1
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: version }),
                new asn1js.Sequence({ value: [] }), // certificate
                new asn1js.Set({
                    value: [new asn1js.Sequence({ value: [] })], // attributes
                }),
            ],
        })

        const info = ExtendedCertificateInfo.fromAsn1(asn1)

        expect(Certificate.fromAsn1).toHaveBeenCalledWith(
            asn1.valueBlock.value[1],
        )
        expect(Attribute.fromAsn1).toHaveBeenCalledWith(
            (asn1.valueBlock.value[2] as asn1js.Set).valueBlock.value[0],
        )
        expect(info.version).toBe(version)
        expect(info.certificate).toBe(mockCertificate)
        expect(info.attributes).toHaveLength(1)
        expect(info.attributes[0]).toBe(mockAttributes[0])
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        // Test with non-Sequence
        const invalidAsn1 = new asn1js.Integer({ value: 1 })
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Test with incorrect number of elements
        const invalidSequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // version
                new asn1js.Sequence({ value: [] }), // certificate
                // Missing attributes
            ],
        })
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for version
        const invalidVersionType = new asn1js.Sequence({
            value: [
                new asn1js.BitString({ valueHex: new Uint8Array([1]) }), // Invalid type
                new asn1js.Sequence({ value: [] }), // certificate
                new asn1js.Set({ value: [] }), // attributes
            ],
        })
        expect(() =>
            ExtendedCertificateInfo.fromAsn1(invalidVersionType),
        ).toThrow('Invalid ASN.1 structure: expected INTEGER for version')

        // Test with incorrect type for certificate
        const invalidCertType = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // version
                new asn1js.Integer({ value: 1 }), // Invalid type
                new asn1js.Set({ value: [] }), // attributes
            ],
        })
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidCertType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for certificate',
        )

        // Test with incorrect type for attributes
        const invalidAttrsType = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // version
                new asn1js.Sequence({ value: [] }), // certificate
                new asn1js.Integer({ value: 1 }), // Invalid type
            ],
        })
        expect(() =>
            ExtendedCertificateInfo.fromAsn1(invalidAttrsType),
        ).toThrow(
            'Invalid ASN.1 structure: expected SET/CONSTRUCTED for Attributes but got Integer',
        )
    })
})
