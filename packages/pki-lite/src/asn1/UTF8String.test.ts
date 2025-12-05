import { describe, expect, test } from 'vitest'
import { UTF8String } from './UTF8String.js'
import { asn1js } from '../core/PkiBase.js'

describe('UTF8String', () => {
    test('should create UTF8String from string value', () => {
        const testString = 'Hello, World!'
        const utf8String = new UTF8String({ value: testString })

        expect(utf8String).toBeInstanceOf(UTF8String)
        expect(utf8String.toString()).toEqual(testString)

        // Should encode as UTF-8 bytes
        const expectedBytes = new TextEncoder().encode(testString)
        expect(utf8String.bytes).toEqual(expectedBytes)
    })

    test('should create UTF8String from Uint8Array<ArrayBuffer>', () => {
        const bytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
        const utf8String = new UTF8String({ value: bytes })

        expect(utf8String.bytes).toEqual(bytes)
        expect(utf8String.toString()).toEqual('Hello')
    })

    test('should create UTF8String from another UTF8String', () => {
        const original = new UTF8String({ value: 'Original String' })
        const copy = new UTF8String({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toEqual(original.toString())
    })

    test('should handle Unicode characters', () => {
        const unicodeString = '你好世界! 🌍 éñüçáóú'
        const utf8String = new UTF8String({ value: unicodeString })

        expect(utf8String.toString()).toEqual(unicodeString)

        // Verify UTF-8 encoding
        const expectedBytes = new TextEncoder().encode(unicodeString)
        expect(utf8String.bytes).toEqual(expectedBytes)
    })

    test('should handle empty string', () => {
        const utf8String = new UTF8String({ value: '' })

        expect(utf8String.bytes.length).toEqual(0)
        expect(utf8String.toString()).toEqual('')
    })

    test('should convert to ASN.1 structure correctly', () => {
        const testString = 'Test ASN.1'
        const utf8String = new UTF8String({ value: testString })
        const asn1 = utf8String.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Utf8String)

        // Verify the bytes are preserved in ASN.1
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        const expectedBytes = new TextEncoder().encode(testString)
        expect(valueHex).toEqual(expectedBytes)
    })

    test('should parse from ASN.1 structure correctly', () => {
        const testString = 'ASN.1 Test String'
        const asn1 = new asn1js.Utf8String({ value: testString })

        const utf8String = UTF8String.fromAsn1(asn1)

        expect(utf8String).toBeInstanceOf(UTF8String)
        expect(utf8String.toString()).toEqual(testString)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => UTF8String.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected UTF8String',
        )
    })

    test('should convert to hex string', () => {
        const testCases = [
            { input: 'A', expected: '41' },
            { input: 'AB', expected: '4142' },
            { input: 'Hello', expected: '48656c6c6f' },
            { input: '', expected: '' },
        ]

        for (const { input, expected } of testCases) {
            const utf8String = new UTF8String({ value: input })
            expect(utf8String.toHexString().toLowerCase()).toEqual(expected)
        }
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testStrings = [
            'Simple ASCII',
            'Unicode: 🌟✨💫',
            'Mixed: Hello世界123!',
            '',
            'Special chars: !@#$%^&*()',
        ]

        for (const testString of testStrings) {
            const original = new UTF8String({ value: testString })
            const asn1 = original.toAsn1()
            const decoded = UTF8String.fromAsn1(asn1)

            expect(decoded.toString()).toEqual(testString)
            expect(decoded.bytes).toEqual(original.bytes)
        }
    })
})
