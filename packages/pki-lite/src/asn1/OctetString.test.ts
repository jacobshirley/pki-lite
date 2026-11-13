import { describe, expect, test } from 'vitest'
import { der, derToAsn1, UniversalTag } from '../core/PkiBase.js'
import { OctetString } from './OctetString.js'

describe('OctetString', () => {
    // Sample test data
    const binaryData = new Uint8Array([
        0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0xfd, 0xfc,
    ])
    const textString = 'Hello, World!'

    test('constructor creates OctetString from Uint8Array<ArrayBuffer>', () => {
        const octetString = new OctetString({ bytes: binaryData })

        expect(octetString).toBeInstanceOf(OctetString)
        expect(octetString.bytes).toEqual(binaryData)
    })

    test('constructor creates OctetString from string', () => {
        const octetString = new OctetString({ bytes: textString })

        expect(octetString).toBeInstanceOf(OctetString)
        // String should be encoded as UTF-8
        const expectedBytes = new TextEncoder().encode(textString)
        expect(octetString.bytes).toEqual(expectedBytes)
    })

    test('constructor creates OctetString from another OctetString', () => {
        const original = new OctetString({ bytes: binaryData })
        const copy = new OctetString({ bytes: original })

        expect(copy).toBeInstanceOf(OctetString)
        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.bytes).toEqual(binaryData)

        // Verify they are separate instances (deep copy)
        const modifiedBytes = new Uint8Array(binaryData)
        modifiedBytes[0] = 0xff
        original.bytes = modifiedBytes

        expect(copy.bytes).not.toEqual(original.bytes)
    })

    test('toAsn1 creates correct ASN.1 structure', () => {
        const octetString = new OctetString({ bytes: binaryData })
        const asn1 = octetString.toAsn1()

        expect(asn1.is(UniversalTag.OctetString)).toBe(true)

        // Check the value is preserved
        const valueHex = asn1.content
        expect(valueHex).toEqual(binaryData)
    })

    test('fromAsn1 parses ASN.1 structure correctly', () => {
        // Create an ASN.1 structure
        const asn1 = der.octetString(binaryData)

        const octetString = OctetString.fromAsn1(asn1)

        expect(octetString).toBeInstanceOf(OctetString)
        expect(octetString.bytes).toEqual(binaryData)
    })

    test('fromAsn1 throws on invalid ASN.1 structure', () => {
        // Not an OctetString
        const invalidAsn1 = der.integer(123)

        expect(() => OctetString.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected OCTET STRING',
        )
    })

    test('toDer/fromDer roundtrip works correctly', () => {
        const originalOctetString = new OctetString({ bytes: binaryData })
        const encoded = originalOctetString.toDer()

        // Manually parse DER back to ASN.1
        const asn1 = derToAsn1(encoded)
        const parsedOctetString = OctetString.fromAsn1(asn1)

        expect(parsedOctetString.bytes).toEqual(originalOctetString.bytes)
    })

    test('handles empty octet string', () => {
        const emptyBytes = new Uint8Array(0)
        const octetString = new OctetString({ bytes: emptyBytes })

        expect(octetString.bytes).toEqual(emptyBytes)
        expect(octetString.bytes.length).toEqual(0)

        // Test ASN.1 conversion
        const asn1 = octetString.toAsn1()
        const valueHex = asn1.content
        expect(valueHex.length).toEqual(0)
    })

    test('handles large octet strings', () => {
        // Create a large byte array (10KB)
        const largeBytes = new Uint8Array(10240)
        for (let i = 0; i < largeBytes.length; i++) {
            largeBytes[i] = i % 256
        }

        const octetString = new OctetString({ bytes: largeBytes })
        expect(octetString.bytes.length).toEqual(10240)
        expect(octetString.bytes).toEqual(largeBytes)

        // Test ASN.1 conversion
        const asn1 = octetString.toAsn1()
        const valueHex = asn1.content
        expect(valueHex.length).toEqual(10240)
        expect(valueHex).toEqual(largeBytes)
    })

    test('handles non-ASCII Unicode strings', () => {
        // String with various Unicode characters
        const unicodeString = 'Hello, 世界! áéíóú ñ € 😊 𝄞'
        const octetString = new OctetString({ bytes: unicodeString })

        // Verify the UTF-8 encoding
        const expectedBytes = new TextEncoder().encode(unicodeString)
        expect(octetString.bytes).toEqual(expectedBytes)

        // Verify roundtrip through ASN.1
        const asn1 = octetString.toAsn1()
        const parsed = OctetString.fromAsn1(asn1)

        // The bytes should be preserved exactly
        expect(parsed.bytes).toEqual(expectedBytes)

        // Converting back to a string should yield the original
        const decodedString = new TextDecoder().decode(parsed.bytes)
        expect(decodedString).toEqual(unicodeString)
    })

    test('toString returns string representation', () => {
        // For a text string, toString should show the string content
        const textOctetString = new OctetString({ bytes: textString })
        expect(textOctetString.toString()).toContain('OctetString')

        // For binary data, toString should show the OctetString type
        const binaryOctetString = new OctetString({ bytes: binaryData })
        expect(binaryOctetString.toString()).toContain('OctetString')
    })
})
