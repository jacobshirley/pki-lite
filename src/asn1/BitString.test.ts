import { describe, expect, test } from 'vitest'
import { BitString } from './BitString.js'
import * as asn1js from 'asn1js'

describe('BitString', () => {
    // Basic constructor tests
    test('should correctly initialize with string value', () => {
        const testString = 'Test BitString data'
        const bitString = new BitString({ value: testString })

        // The bytes should match the UTF-8 encoding of the string
        const expectedBytes = new TextEncoder().encode(testString)
        expect(bitString.bytes).toEqual(expectedBytes)

        // ToString should convert back to the original string
        expect(bitString.toString()).toBe(testString)
    })

    test('should correctly initialize with Uint8Array', () => {
        const bytes = new Uint8Array([0x54, 0x65, 0x73, 0x74]) // "Test" in ASCII
        const bitString = new BitString({ value: bytes })

        expect(bitString.bytes).toEqual(bytes)
        expect(bitString.toString()).toBe('Test')
    })

    test('should correctly initialize from another BitString', () => {
        const original = new BitString({ value: 'Original BitString' })
        const copy = new BitString({ value: original })

        // Both should have the same bytes
        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toBe(original.toString())

        // Verify they are separate instances
        const newBytes = new TextEncoder().encode('Modified')
        original.bytes = newBytes
        expect(original.bytes).toEqual(newBytes)
        expect(copy.bytes).not.toEqual(newBytes)
    })

    // ASN.1 conversion tests
    test('should correctly convert to and from ASN.1', () => {
        const testString = 'ASN.1 Test'
        const original = new BitString({ value: testString })

        const asn1 = original.toAsn1()

        // Verify it's the correct ASN.1 type
        expect(asn1).toBeInstanceOf(asn1js.BitString)

        // Convert back using fromAsn1
        const decoded = BitString.fromAsn1(asn1)

        // Verify round-trip conversion
        expect(decoded.bytes).toEqual(original.bytes)
        expect(decoded.toString()).toBe(testString)
    })

    // Test fromAsn1 with invalid input
    test('fromAsn1 should throw error for non-BIT STRING ASN.1 types', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([42]),
        })
        expect(() => BitString.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected BIT STRING',
        )
    })

    // Test with empty values
    test('should handle empty string', () => {
        const bitString = new BitString({ value: '' })
        expect(bitString.bytes.length).toBe(0)
        expect(bitString.toString()).toBe('')
    })

    // Test with binary data
    test('should handle binary data', () => {
        // Create a Uint8Array with non-UTF8 data
        const binaryData = new Uint8Array([0x00, 0xff, 0xa0, 0x5f, 0x7e])
        const bitString = new BitString({ value: binaryData })

        expect(bitString.bytes).toEqual(binaryData)

        // toAsn1 should preserve the binary data
        const asn1 = bitString.toAsn1() as asn1js.BitString
        expect(new Uint8Array(asn1.valueBlock.valueHexView)).toEqual(binaryData)

        // Round-trip via fromAsn1
        const roundTrip = BitString.fromAsn1(asn1)
        expect(roundTrip.bytes).toEqual(binaryData)
    })

    // Test with large data
    test('should handle large data', () => {
        // Create a larger string
        const largeString = 'A'.repeat(1000)
        const bitString = new BitString({ value: largeString })

        expect(bitString.bytes.length).toBe(1000)
        expect(bitString.toString()).toBe(largeString)
    })

    // Test with special characters
    test('should handle special characters', () => {
        const specialChars = '!@#$%^&*()_+{}[]|":;<>,.?/~`éñüçあいうえお😀😎🚀'
        const bitString = new BitString({ value: specialChars })

        expect(bitString.toString()).toBe(specialChars)
    })

    // Test toString method
    test('toString should convert bytes back to string', () => {
        const testCases = [
            'Simple ASCII string',
            'String with numbers 12345',
            'String with symbols !@#$%',
            'Unicode characters: 你好世界',
            'Emojis: 😀😎🚀',
            '', // Empty string
        ]

        for (const testCase of testCases) {
            const bitString = new BitString({ value: testCase })
            expect(bitString.toString()).toBe(testCase)
        }
    })

    // Test toHexString method
    test('toHexString should convert bytes to hex string', () => {
        const testCases = [
            { input: new Uint8Array([0x00]), expected: '00' },
            { input: new Uint8Array([0x12, 0x34]), expected: '1234' },
            { input: new Uint8Array([0xab, 0xcd, 0xef]), expected: 'abcdef' },
            { input: new Uint8Array([0xff, 0x00, 0xff]), expected: 'ff00ff' },
            { input: new TextEncoder().encode('ABC'), expected: '414243' },
        ]

        for (const { input, expected } of testCases) {
            const bitString = new BitString({ value: input })
            expect(bitString.toHexString().toLowerCase()).toBe(expected)
        }
    })
})
