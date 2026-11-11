import { describe, expect, test } from 'vitest'
import { UniversalString } from './UniversalString.js'
import * as asn1js from 'asn1js'

/** UTF-32BE, the UniversalString encoding */
const utf32 = (value: string) => {
    const points = Array.from(value, (c) => c.codePointAt(0)!)
    const bytes = new Uint8Array(points.length * 4)
    points.forEach((p, i) => new DataView(bytes.buffer).setUint32(i * 4, p))
    return bytes
}

describe('UniversalString', () => {
    test('should create UniversalString from string value', () => {
        const testString = 'Hello, Universal!'
        const universalString = new UniversalString({ value: testString })

        expect(universalString).toBeInstanceOf(UniversalString)
        expect(universalString.toString()).toEqual(testString)

        // Should encode as UTF-8 bytes
        const expectedBytes = utf32(testString)
        expect(universalString.bytes).toEqual(expectedBytes)
    })

    test('should create UniversalString from Uint8Array<ArrayBuffer>', () => {
        const bytes = utf32('Universal')
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
        const expectedBytes = utf32(unicodeString)
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

        expect(asn1).toBeInstanceOf(asn1js.UniversalString)

        // Verify the bytes are preserved in ASN.1
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        const expectedBytes = utf32(testString)
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
            { input: 'A', expected: '00000041' },
            { input: 'UNI', expected: '000000550000004e00000049' },
            { input: '123', expected: '000000310000003200000033' },
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

    test('encodes as UTF-32BE and round-trips characters outside the BMP', () => {
        const value = 'a😀'
        const universalString = new UniversalString({ value })
        expect(universalString.bytes).toEqual(
            new Uint8Array([0, 0, 0, 0x61, 0, 1, 0xf6, 0]),
        )
        const parsed = UniversalString.fromAsn1(universalString.toAsn1())
        expect(parsed.toString()).toBe(value)
    })
})
