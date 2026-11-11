import { describe, expect, test } from 'vitest'
import { der, UniversalTag } from '../core/PkiBase.js'
import { UniversalString } from './UniversalString.js'

describe('UniversalString', () => {
    test('should create UniversalString from string value', () => {
        const testString = 'Hello, Universal!'
        const universalString = new UniversalString({ value: testString })

        expect(universalString).toBeInstanceOf(UniversalString)
        expect(universalString.toString()).toEqual(testString)

        // Should encode as UTF-8 bytes
        const expectedBytes = new TextEncoder().encode(testString)
        expect(universalString.bytes).toEqual(expectedBytes)
    })

    test('should create UniversalString from Uint8Array<ArrayBuffer>', () => {
        const bytes = new Uint8Array([
            0x55, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6c,
        ]) // "Universal"
        const universalString = new UniversalString({ value: bytes })

        expect(universalString.bytes).toEqual(bytes)
        expect(universalString.toString()).toEqual('Universal')
    })

    test('should create UniversalString from another UniversalString', () => {
        const original = new UniversalString({ value: 'Original Universal' })
        const copy = new UniversalString({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toEqual(original.toString())
    })

    test('should handle Unicode characters', () => {
        const unicodeString = 'Universal: 世界 🌍 αβγ'
        const universalString = new UniversalString({ value: unicodeString })

        expect(universalString.toString()).toEqual(unicodeString)

        // Verify UTF-8 encoding
        const expectedBytes = new TextEncoder().encode(unicodeString)
        expect(universalString.bytes).toEqual(expectedBytes)
    })

    test('should handle empty string', () => {
        const universalString = new UniversalString({ value: '' })

        expect(universalString.bytes.length).toEqual(0)
        expect(universalString.toString()).toEqual('')
    })

    test('should convert to ASN.1 structure correctly', () => {
        const testString = 'Test Universal'
        const universalString = new UniversalString({ value: testString })
        const asn1 = universalString.toAsn1()

        expect(asn1.is(UniversalTag.UniversalString)).toBe(true)

        // Verify the bytes are preserved in ASN.1
        const valueHex = asn1.content
        const expectedBytes = new TextEncoder().encode(testString)
        expect(valueHex).toEqual(expectedBytes)
    })

    test('should parse from ASN.1 structure correctly', () => {
        // UniversalString has complex encoding, so we'll just test the basic structure
        const testBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
        const asn1 = der.primitive(UniversalTag.UniversalString, testBytes)

        const universalString = UniversalString.fromAsn1(asn1)

        expect(universalString).toBeInstanceOf(UniversalString)
        expect(universalString.bytes).toEqual(testBytes)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = der.octetString(new Uint8Array([1, 2, 3]))

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
            expect(universalString.toHexString().toLowerCase()).toEqual(
                expected,
            )
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

            expect(decoded.toString()).toEqual(testString)
            expect(decoded.bytes).toEqual(original.bytes)
        }
    })

    test('should handle full Unicode range', () => {
        // Universal string supports the full Unicode range
        const unicodeChars = 'Unicode: αβγδε ñüç 中文 русский 🌟✨💫'
        const universalString = new UniversalString({ value: unicodeChars })

        expect(universalString.toString()).toEqual(unicodeChars)

        // Test round-trip
        const asn1 = universalString.toAsn1()
        const decoded = UniversalString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(unicodeChars)
    })

    test('should handle mathematical symbols', () => {
        const mathString = '∑∆∇∈∉∊∋∌∍∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪'
        const universalString = new UniversalString({ value: mathString })

        expect(universalString.toString()).toEqual(mathString)

        // Test round-trip
        const asn1 = universalString.toAsn1()
        const decoded = UniversalString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(mathString)
    })

    test('should handle emoji and extended Unicode', () => {
        const emojiString = '👋🌍🚀🎉🔥💯⭐️🌟✨💫🎈🎁🎊'
        const universalString = new UniversalString({ value: emojiString })

        expect(universalString.toString()).toEqual(emojiString)

        // Test round-trip
        const asn1 = universalString.toAsn1()
        const decoded = UniversalString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(emojiString)
    })
})
