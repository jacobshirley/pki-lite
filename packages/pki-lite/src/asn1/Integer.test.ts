import { describe, expect, test } from 'vitest'
import { Integer } from './Integer.js'
import * as asn1js from 'asn1js'

describe('Integer', () => {
    // Small number tests
    test('should correctly handle small numbers', () => {
        const testCases = [
            { input: 0, expected: [0] },
            { input: 1, expected: [1] },
            { input: 42, expected: [42] },
            { input: 127, expected: [127] },
            { input: 255, expected: [0, 255] }, // In ASN.1, 255 needs a leading 0 to indicate it's positive
        ]

        for (const { input, expected } of testCases) {
            const integer = new Integer({ value: input })
            expect(integer.bytes).toEqual(new Uint8Array(expected))
            expect(integer.toInteger()).toBe(input)
            expect(integer.toString()).toBe(String(input))
        }
    })

    // String number tests
    test('should correctly parse number strings', () => {
        const testCases = [
            { input: '0', expected: [0] },
            { input: '42', expected: [42] },
            { input: '127', expected: [127] },
            { input: '255', expected: [0, 255] }, // Values 128-255 need a leading 0 to indicate positive
        ]

        for (const { input, expected } of testCases) {
            const integer = new Integer({ value: input })
            expect(integer.bytes).toEqual(new Uint8Array(expected))
            expect(integer.toString()).toBe(input)
        }
    })

    // Invalid string test
    test('should throw error for invalid number strings', () => {
        expect(() => new Integer({ value: 'not-a-number' })).toThrow(
            'Invalid number string',
        )
    })

    // Copy constructor test
    test('should correctly use copy constructor', () => {
        const original = new Integer({ value: 42 })
        const copy = new Integer({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toInteger()).toBe(original.toInteger())
    })

    // ASN.1 encoding/decoding tests
    test('should correctly convert to and from ASN.1', () => {
        const testValues = [0, 1, 42, 127, 255]

        for (const value of testValues) {
            const integer = new Integer({ value: value })
            const asn1 = integer.toAsn1()

            // Check that the ASN.1 object is correct
            expect(asn1).toBeInstanceOf(asn1js.Integer)

            // Round-trip conversion
            const decoded = Integer.fromAsn1(asn1)
            expect(decoded.toInteger()).toBe(value)
        }
    })

    // fromAsn1 with invalid type
    test('fromAsn1 should throw error for non-INTEGER ASN.1 types', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([42]),
        })
        expect(() => Integer.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected INTEGER',
        )
    })

    // Extensions for large numbers
    // Since the current implementation only handles single byte integers,
    // these tests will help guide expansion for large number support

    test('should handle large numbers (multi-byte)', () => {
        const testCases = [
            { input: 256, expected: [1, 0] },
            { input: 1000, expected: [3, 232] },
            { input: 65535, expected: [0, 255, 255] }, // 0xFFFF with leading 0 (positive)
            { input: 16777216, expected: [1, 0, 0, 0] }, // 2^24
        ]

        for (const { input, expected } of testCases) {
            const integer = new Integer({ value: input })
            expect(integer.bytes).toEqual(new Uint8Array(expected))
            expect(integer.toInteger()).toBe(input)
            expect(integer.toString()).toBe(String(input))
        }
    })

    test('should handle negative numbers', () => {
        const testCases = [
            { input: -1, expected: [255] },
            { input: -127, expected: [129] },
            { input: -128, expected: [128] },
            { input: -129, expected: [255, 127] },
            { input: -256, expected: [255, 0] },
        ]

        for (const { input, expected } of testCases) {
            const integer = new Integer({ value: input })
            expect(integer.bytes).toEqual(new Uint8Array(expected))
            expect(integer.toInteger()).toBe(input)
            expect(integer.toString()).toBe(String(input))
        }
    })

    test('should handle very large numbers using BigInt', () => {
        // Test with a value that exceeds Number.MAX_SAFE_INTEGER
        const bigIntValue = BigInt('9007199254740992') // 2^53
        const integer = new Integer({ value: bigIntValue })

        // Verify bytes representation
        expect(integer.bytes.length).toBeGreaterThan(6) // Should be multi-byte

        // Verify string representation
        expect(integer.toString()).toBe('9007199254740992')

        // Test round-trip conversion
        expect(integer.toBigInt()).toBe(bigIntValue)
    })

    test('should handle BigInt values', () => {
        const testCases = [
            { input: 0n, expected: [0] },
            { input: 42n, expected: [42] },
            { input: 255n, expected: [0, 255] },
            { input: 256n, expected: [1, 0] },
            { input: 65536n, expected: [1, 0, 0] },
            { input: -1n, expected: [255] },
            { input: -256n, expected: [255, 0] },
            { input: -32768n, expected: [128, 0] }, // -2^15
        ]

        for (const { input, expected } of testCases) {
            const integer = new Integer({ value: input })
            expect(integer.bytes).toEqual(new Uint8Array(expected))
            expect(integer.toBigInt()).toBe(input)
            expect(integer.toString()).toBe(input.toString())
        }
    })

    test('convert to hex strings', () => {
        const testCases = [
            { input: 0n, expected: '00' },
            { input: 42n, expected: '2a' },
            { input: 255n, expected: 'ff' },
            { input: 256n, expected: '0100' },
            { input: 65536n, expected: '010000' },
            { input: -1n, expected: 'ff' },
            { input: -256n, expected: 'ff00' },
            { input: -32768n, expected: '8000' }, // -2^15
            { input: 0x1234n, expected: '1234' },
            { input: 0x123456n, expected: '123456' },
            { input: -0x1234n, expected: 'edcc' }, // two's complement of 0x1234
        ]

        for (const { input, expected } of testCases) {
            const integer = new Integer({ value: input })
            expect(integer.toHexString()).toBe(expected)
        }
    })
})
