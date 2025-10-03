import { describe, expect, test } from 'vitest'
import { ObjectIdentifier } from './ObjectIdentifier.js'
import * as asn1js from 'asn1js'

describe('ObjectIdentifier', () => {
    test('should create ObjectIdentifier from string value', () => {
        const oidString = '1.2.3.4.5'
        const oid = new ObjectIdentifier({ value: oidString })

        expect(oid).toBeInstanceOf(ObjectIdentifier)
        expect(oid.value).toEqual(oidString)
        expect(oid.toString()).toEqual(oidString)
    })

    test('should create ObjectIdentifier from another ObjectIdentifier', () => {
        const original = new ObjectIdentifier({ value: '1.2.840.113549.1.1.1' })
        const copy = new ObjectIdentifier({ value: original })

        expect(copy.value).toEqual(original.value)
        expect(copy.toString()).toEqual(original.toString())
    })

    test('should handle common OID values', () => {
        const testOids = [
            '1.2.840.113549.1.1.1', // RSA encryption
            '1.2.840.10045.2.1', // EC key
            '2.5.29.15', // Key usage
            '2.5.29.19', // Basic constraints
            '1.3.6.1.5.5.7.3.1', // Server authentication
            '0.0', // Minimal OID
        ]

        for (const oidString of testOids) {
            const oid = new ObjectIdentifier({ value: oidString })
            expect(oid.value).toEqual(oidString)
            expect(oid.toString()).toEqual(oidString)
        }
    })

    test('should throw error for null or undefined value', () => {
        expect(() => new ObjectIdentifier({ value: null as any })).toThrow(
            'ObjectIdentifier value cannot be undefined or null',
        )
        expect(() => new ObjectIdentifier({ value: undefined as any })).toThrow(
            'ObjectIdentifier value cannot be undefined or null',
        )
    })

    test('should handle object with toString method', () => {
        const objectWithToString = {
            toString: () => '1.2.3.4.5.6',
        }
        const oid = new ObjectIdentifier({ value: objectWithToString as any })

        expect(oid.value).toEqual('1.2.3.4.5.6')
        expect(oid.toString()).toEqual('1.2.3.4.5.6')
    })

    test('should handle objects with toString method correctly', () => {
        // Test valid objects with toString
        const validValues = [
            123, // has toString
            true, // has toString
            [], // has toString
            {}, // has toString
        ]

        for (const validValue of validValues) {
            const oid = new ObjectIdentifier({ value: validValue as any })
            expect(oid.value).toEqual(validValue.toString())
        }
    })

    test('should convert to ASN.1 structure correctly', () => {
        const oidString = '1.2.840.113549.1.1.11'
        const oid = new ObjectIdentifier({ value: oidString })
        const asn1 = oid.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.ObjectIdentifier)

        // Verify the value is preserved in ASN.1
        const asn1Oid = asn1 as asn1js.ObjectIdentifier
        expect(asn1Oid.valueBlock.toString()).toEqual(oidString)
    })

    test('should parse from ASN.1 structure correctly', () => {
        const oidString = '2.5.29.14'
        const asn1 = new asn1js.ObjectIdentifier({ value: oidString })

        const oid = ObjectIdentifier.fromAsn1(asn1)

        expect(oid).toBeInstanceOf(ObjectIdentifier)
        expect(oid.value).toEqual(oidString)
        expect(oid.toString()).toEqual(oidString)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => ObjectIdentifier.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
        )
    })

    test('fromAsn1 should throw error for empty OID value', () => {
        // Create a mock ASN.1 ObjectIdentifier with no value
        const mockAsn1 = new asn1js.ObjectIdentifier()
        // Mock the valueBlock.toString to return empty string
        mockAsn1.valueBlock.toString = () => ''

        expect(() => ObjectIdentifier.fromAsn1(mockAsn1)).toThrow(
            'Invalid ObjectIdentifier: no value found in ASN.1 structure',
        )
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testOids = [
            '1.2.840.113549.1.1.1',
            '1.3.6.1.5.5.7.3.1',
            '2.5.29.15',
            '1.2.3',
            '0.0',
        ]

        for (const oidString of testOids) {
            const original = new ObjectIdentifier({ value: oidString })
            const asn1 = original.toAsn1()
            const decoded = ObjectIdentifier.fromAsn1(asn1)

            expect(decoded.value).toEqual(oidString)
            expect(decoded.toString()).toEqual(oidString)
        }
    })

    test('should handle standard algorithm OIDs', () => {
        const algorithmOids = {
            RSA: '1.2.840.113549.1.1.1',
            'SHA-256': '2.16.840.1.101.3.4.2.1',
            'SHA-1': '1.3.14.3.2.26',
            EC: '1.2.840.10045.2.1',
            'RSA with SHA-256': '1.2.840.113549.1.1.11',
        }

        for (const [name, oidString] of Object.entries(algorithmOids)) {
            const oid = new ObjectIdentifier({ value: oidString })
            expect(oid.value).toEqual(oidString)

            // Test round-trip
            const asn1 = oid.toAsn1()
            const decoded = ObjectIdentifier.fromAsn1(asn1)
            expect(decoded.value).toEqual(oidString)
        }
    })

    test('should handle X.500 attribute type OIDs', () => {
        const x500Oids = {
            CN: '2.5.4.3',
            O: '2.5.4.10',
            OU: '2.5.4.11',
            C: '2.5.4.6',
            ST: '2.5.4.8',
            L: '2.5.4.7',
        }

        for (const [name, oidString] of Object.entries(x500Oids)) {
            const oid = new ObjectIdentifier({ value: oidString })
            expect(oid.value).toEqual(oidString)

            // Test round-trip
            const asn1 = oid.toAsn1()
            const decoded = ObjectIdentifier.fromAsn1(asn1)
            expect(decoded.value).toEqual(oidString)
        }
    })
})
