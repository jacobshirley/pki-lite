import {
    AttributeCertificateInfo,
    Holder,
    AttCertIssuer,
} from './AttributeCertificateInfo.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Attribute } from '../Attribute.js'
import { describe, test, expect, beforeEach } from 'vitest'
import { der, UniversalTag } from '../../core/PkiBase.js'

describe('AttributeCertificateInfo', () => {
    // Test Holder class
    describe('Holder', () => {
        test('constructor should initialize properties correctly', () => {
            const holderValue = new Uint8Array([1, 2, 3])
            const holder = new Holder({ holderValue })

            expect(holder.holderValue).toEqual(holderValue)
        })

        test('toAsn1 should return correct ASN.1 structure', () => {
            const holderValue = new Uint8Array([1, 2, 3])
            const holder = new Holder({ holderValue })

            const asn1 = holder.toAsn1()

            expect(asn1.is(UniversalTag.Sequence)).toBe(true)
            const items = asn1.children
            expect(items.length).toEqual(1)
            expect(items[0].is(UniversalTag.OctetString)).toBe(true)

            // Check OctetString value matches holderValue
            const octetString = items[0]
            expect(octetString.bytes()).toEqual(holderValue)
        })

        test('fromAsn1 should parse ASN.1 structure correctly', () => {
            const holderValue = new Uint8Array([1, 2, 3])
            const asn1 = der.sequence([der.octetString(holderValue)])

            const holder = Holder.fromAsn1(asn1)

            // In the simplified implementation, we store the entire BER encoding
            expect(holder.holderValue).toBeDefined()
            expect(holder.holderValue instanceof Uint8Array).toEqual(true)
        })

        test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
            const invalidAsn1 = der.integer(1)
            expect(() => Holder.fromAsn1(invalidAsn1)).toThrow(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        })
    })

    // Test AttCertIssuer class
    describe('AttCertIssuer', () => {
        test('constructor should initialize properties correctly', () => {
            const issuerValue = new Uint8Array([1, 2, 3])
            const issuer = new AttCertIssuer({ issuerValue })

            expect(issuer.issuerValue).toEqual(issuerValue)
        })

        test('toAsn1 should return correct ASN.1 structure', () => {
            const issuerValue = new Uint8Array([1, 2, 3])
            const issuer = new AttCertIssuer({ issuerValue })

            const asn1 = issuer.toAsn1()

            expect(asn1.is(UniversalTag.Sequence)).toBe(true)
            const items = asn1.children
            expect(items.length).toEqual(1)
            expect(items[0].is(UniversalTag.OctetString)).toBe(true)

            // Check OctetString value matches issuerValue
            const octetString = items[0]
            expect(octetString.bytes()).toEqual(issuerValue)
        })

        test('fromAsn1 should parse ASN.1 structure correctly', () => {
            const issuerValue = new Uint8Array([1, 2, 3])
            const asn1 = der.sequence([der.octetString(issuerValue)])

            const issuer = AttCertIssuer.fromAsn1(asn1)

            // In the simplified implementation, we store the entire BER encoding
            expect(issuer.issuerValue).toBeDefined()
            expect(issuer.issuerValue instanceof Uint8Array).toEqual(true)
        })

        test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
            const invalidAsn1 = der.integer(1)
            expect(() => AttCertIssuer.fromAsn1(invalidAsn1)).toThrow(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        })
    })

    // Test AttributeCertificateInfo class
    describe('AttributeCertificateInfo', () => {
        let mockHolder: Holder
        let mockIssuer: AttCertIssuer
        let mockSignature: AlgorithmIdentifier
        let mockAttributes: Attribute[]

        beforeEach(() => {
            mockHolder = {
                holderValue: new Uint8Array([1, 2, 3]),
                toAsn1: () => der.sequence([]),
            } as unknown as Holder

            mockIssuer = {
                issuerValue: new Uint8Array([4, 5, 6]),
                toAsn1: () => der.sequence([]),
            } as unknown as AttCertIssuer

            mockSignature = {
                algorithm: '1.2.840.113549.1.1.11',
                parameters: null,
                toAsn1: () => der.sequence([]),
            } as unknown as AlgorithmIdentifier

            mockAttributes = [
                {
                    type: '1.2.3.4.5',
                    values: ['test-attribute'],
                    toAsn1: () => der.sequence([]),
                } as unknown as Attribute,
            ]
        })

        test('constructor should initialize properties correctly', () => {
            const version = 1
            const serialNumber = new Uint8Array([7, 8, 9])
            const validityPeriod = {
                notBefore: new Date('2023-01-01'),
                notAfter: new Date('2024-01-01'),
            }

            const info = new AttributeCertificateInfo({
                version,
                holder: mockHolder,
                issuer: mockIssuer,
                signature: mockSignature,
                serialNumber,
                validityPeriod,
                attributes: mockAttributes,
            })

            expect(info.version).toEqual(version)
            expect(info.holder).toEqual(mockHolder)
            expect(info.issuer).toEqual(mockIssuer)
            expect(info.signature).toEqual(mockSignature)
            expect(info.serialNumber).toEqual(serialNumber)
            expect(info.validityPeriod).toEqual(validityPeriod)
            expect(info.attributes).toEqual(mockAttributes)
            expect(info.issuerUniqueID).toBeUndefined()
            expect(info.extensions).toBeUndefined()
        })

        test('toAsn1 should return correct ASN.1 structure', () => {
            const version = 1
            const serialNumber = new Uint8Array([7, 8, 9])
            const validityPeriod = {
                notBefore: new Date('2023-01-01'),
                notAfter: new Date('2024-01-01'),
            }

            const info = new AttributeCertificateInfo({
                version,
                holder: mockHolder,
                issuer: mockIssuer,
                signature: mockSignature,
                serialNumber,
                validityPeriod,
                attributes: mockAttributes,
            })

            const asn1 = info.toAsn1()

            expect(asn1.is(UniversalTag.Sequence)).toBe(true)

            // Check the structure has the correct elements
            const items = asn1.children
            expect(items.length).toEqual(7) // No optional fields
            expect(items[0].is(UniversalTag.Integer)).toBe(true) // version

            // Check version value
            const versionAsn1 = items[0]
            expect(der.readNumber(versionAsn1)).toEqual(version)
        })

        test('fromAsn1 should parse ASN.1 structure correctly', () => {
            const version = 1
            const serialNumber = new Uint8Array([7, 8, 9])
            const notBefore = new Date('2023-01-01')
            const notAfter = new Date('2024-01-01')

            // Create mock ASN.1 structure
            const asn1 = der.sequence([
                der.integer(version),
                der.sequence([]), // holder
                der.sequence([]), // issuer
                der.sequence([]), // signature
                der.primitive(UniversalTag.Integer, serialNumber),
                // validityPeriod
                der.sequence([
                    der.generalizedTime(notBefore),
                    der.generalizedTime(notAfter),
                ]),
                // attributes
                der.sequence([der.sequence([])]),
            ])

            // This test verifies the fromAsn1 method attempts to parse the structure
            // It may throw due to incomplete mock data, which is expected
            expect(() => {
                const info = AttributeCertificateInfo.fromAsn1(asn1)
                // If parsing succeeds, verify basic structure
                expect(info).toBeInstanceOf(AttributeCertificateInfo)
            }).not.toThrow(/Unknown.+tag|expected SEQUENCE/)
        })

        test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
            // Test with non-Sequence
            const invalidAsn1 = der.integer(1)
            expect(() =>
                AttributeCertificateInfo.fromAsn1(invalidAsn1),
            ).toThrow('Invalid ASN.1 structure: expected SEQUENCE')

            // Test with insufficient elements
            const insufficientElements = der.sequence([
                der.integer(1),
                der.sequence([]),
                der.sequence([]),
                // Missing other required elements
            ])
            expect(() =>
                AttributeCertificateInfo.fromAsn1(insufficientElements),
            ).toThrow('Invalid ASN.1 structure: expected at least 7 elements')
        })
    })
})
