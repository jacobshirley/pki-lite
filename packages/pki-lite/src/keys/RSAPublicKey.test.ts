import { describe, expect, test } from 'vitest'
import { der, UniversalTag } from '../core/PkiBase.js'
import { RSAPublicKey } from './RSAPublicKey.js'

describe('RSAPublicKey', () => {
    // Sample test data
    const modulus = new Uint8Array([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
    ])

    const publicExponent = new Uint8Array([0x01, 0x00, 0x01]) // 65537

    test('constructor creates a valid RSAPublicKey', () => {
        const key = new RSAPublicKey({ modulus, publicExponent })

        expect(key.modulus).toEqual(modulus)
        expect(key.publicExponent).toEqual(publicExponent)
    })

    test('toAsn1 creates correct ASN.1 structure', () => {
        const key = new RSAPublicKey({ modulus, publicExponent })
        const asn1 = key.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        const values = asn1.children
        expect(values.length).toEqual(2)

        // Check modulus
        expect(values[0].is(UniversalTag.Integer)).toBe(true)
        expect(der.readIntegerBytes(values[0])).toEqual(modulus)

        // Check publicExponent
        expect(values[1].is(UniversalTag.Integer)).toBe(true)
        expect(der.readIntegerBytes(values[1])).toEqual(publicExponent)
    })

    test('fromAsn1 parses ASN.1 structure correctly', () => {
        // Create an ASN.1 structure
        const asn1 = der.sequence([
            der.primitive(UniversalTag.Integer, modulus),
            der.primitive(UniversalTag.Integer, publicExponent),
        ])

        const key = RSAPublicKey.fromAsn1(asn1)

        expect(key.modulus).toEqual(modulus)
        expect(key.publicExponent).toEqual(publicExponent)
    })

    test('toDer/fromDer roundtrip works correctly', () => {
        const originalKey = new RSAPublicKey({ modulus, publicExponent })
        const encoded = originalKey.toDer()
        const parsedKey = RSAPublicKey.fromDer(encoded)

        expect(parsedKey.modulus).toEqual(originalKey.modulus)
        expect(parsedKey.publicExponent).toEqual(originalKey.publicExponent)
    })

    test('fromAsn1 throws on invalid ASN.1 structure', () => {
        // Not a sequence
        const invalidAsn1 = der.integer(123)

        expect(() => RSAPublicKey.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Wrong number of elements
        const invalidSequence = der.sequence([der.integer(123)])

        expect(() => RSAPublicKey.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 2 elements',
        )

        // First element not an integer
        const invalidModulus = der.sequence([
            der.octetString(modulus),
            der.primitive(UniversalTag.Integer, publicExponent),
        ])

        expect(() => RSAPublicKey.fromAsn1(invalidModulus)).toThrow(
            'Invalid ASN.1 structure: modulus must be INTEGER',
        )

        // Second element not an integer
        const invalidExponent = der.sequence([
            der.primitive(UniversalTag.Integer, modulus),
            der.octetString(publicExponent),
        ])

        expect(() => RSAPublicKey.fromAsn1(invalidExponent)).toThrow(
            'Invalid ASN.1 structure: publicExponent must be INTEGER',
        )
    })
})
