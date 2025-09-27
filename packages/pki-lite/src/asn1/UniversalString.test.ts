import { describe, expect, test } from 'vitest'
import { UniversalString } from './UniversalString.js'
import * as asn1js from 'asn1js'

describe('UniversalString', () => {
    test('should create UniversalString from string value', () => {
        const testString = 'Hello, Universal!'
        const universalString = new UniversalString({ value: testString })

        expect(universalString).toBeInstanceOf(UniversalString)
        expect(universalString.toString()).toBe(testString)

        // Should encode as UTF-8 bytes
        const expectedBytes = new TextEncoder().encode(testString)
        expect(universalString.bytes).toEqual(expectedBytes)
    })

    test('should create UniversalString from Uint8Array', () => {
        const bytes = new Uint8Array([
            0x55, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6c,
        ]) // "Universal"
        const universalString = new UniversalString({ value: bytes })

        expect(universalString.bytes).toEqual(bytes)
        expect(universalString.toString()).toBe('Universal')
    })

    test('should create UniversalString from another UniversalString', () => {
        const original = new UniversalString({ value: 'Original Universal' })
        const copy = new UniversalString({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toBe(original.toString())
    })

    test('should handle Unicode characters', () => {
        const unicodeString = 'Universal: 世界 🌍 αβγ'
        const universalString = new UniversalString({ value: unicodeString })

        expect(universalString.toString()).toBe(unicodeString)

        // Verify UTF-8 encoding
        const expectedBytes = new TextEncoder().encode(unicodeString)
        expect(universalString.bytes).toEqual(expectedBytes)
    })

    test('should handle empty string', () => {
        const universalString = new UniversalString({ value: '' })

        expect(universalString.bytes.length).toBe(0)
        expect(universalString.toString()).toBe('')
    })

    test('should convert to ASN.1 structure correctly', () => {
        const testString = 'Test Universal'
        const universalString = new UniversalString({ value: testString })
        const asn1 = universalString.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.UniversalString)

        // Verify the bytes are preserved in ASN.1
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        const expectedBytes = new TextEncoder().encode(testString)
        expect(valueHex).toEqual(expectedBytes)
    })

    test('should parse from ASN.1 structure correctly', () => {
        // UniversalString has complex encoding, so we'll just test the basic structure
        const testBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
        const asn1 = new asn1js.UniversalString({ valueHex: testBytes })

        const universalString = UniversalString.fromAsn1(asn1)

        expect(universalString).toBeInstanceOf(UniversalString)
        expect(universalString.bytes).toEqual(testBytes)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => UniversalString.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected UniversalString',
        )
    })

    test('should convert to hex string', () => {
        const testCases = [
            { input: 'A', expected: '41' },
            { input: 'UNI', expected: '554e49' },
            { input: '123', expected: '313233' },
            { input: '', expected: '' },
        ]

        for (const { input, expected } of testCases) {
            const universalString = new UniversalString({ value: input })
            expect(universalString.toHexString().toLowerCase()).toBe(expected)
        }
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testStrings = [
            'Simple Universal',
            'Universal String 123',
            '',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
        ]

        for (const testString of testStrings) {
            const original = new UniversalString({ value: testString })
            const asn1 = original.toAsn1()
            const decoded = UniversalString.fromAsn1(asn1)

            expect(decoded.toString()).toBe(testString)
            expect(decoded.bytes).toEqual(original.bytes)
        }
    })

    test('should handle full Unicode range', () => {
        // Universal string supports the full Unicode range
        const unicodeChars = 'Unicode: αβγδε ñüç 中文 русский 🌟✨💫'
        const universalString = new UniversalString({ value: unicodeChars })

        expect(universalString.toString()).toBe(unicodeChars)

        // Test round-trip
        const asn1 = universalString.toAsn1()
        const decoded = UniversalString.fromAsn1(asn1)
        expect(decoded.toString()).toBe(unicodeChars)
    })

    test('should handle mathematical symbols', () => {
        const mathString = '∑∆∇∈∉∊∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪'
        const universalString = new UniversalString({ value: mathString })

        expect(universalString.toString()).toBe(mathString)

        // Test round-trip
        const asn1 = universalString.toAsn1()
        const decoded = UniversalString.fromAsn1(asn1)
        expect(decoded.toString()).toBe(mathString)
    })

    test('should handle emoji and extended Unicode', () => {
        const emojiString = '👋🌍🚀🎉🔥💯⭐️🌟✨💫🎈🎁🎊'
        const universalString = new UniversalString({ value: emojiString })

        expect(universalString.toString()).toBe(emojiString)

        // Test round-trip
        const asn1 = universalString.toAsn1()
        const decoded = UniversalString.fromAsn1(asn1)
        expect(decoded.toString()).toBe(emojiString)
    })
})
