import { describe, expect, test } from 'vitest'
import { TeletexString } from './TeletexString.js'
import * as asn1js from 'asn1js'

describe('TeletexString', () => {
    test('should create TeletexString from string value', () => {
        const testString = 'Hello, Telex!'
        const teletexString = new TeletexString({ value: testString })

        expect(teletexString).toBeInstanceOf(TeletexString)
        expect(teletexString.toString()).toEqual(testString)

        // Should encode as UTF-8 bytes
        const expectedBytes = new TextEncoder().encode(testString)
        expect(teletexString.bytes).toEqual(expectedBytes)
    })

    test('should create TeletexString from Uint8Array<ArrayBuffer>', () => {
        const bytes = new Uint8Array([0x54, 0x65, 0x6c, 0x65, 0x78]) // "Telex"
        const teletexString = new TeletexString({ value: bytes })

        expect(teletexString.bytes).toEqual(bytes)
        expect(teletexString.toString()).toEqual('Telex')
    })

    test('should create TeletexString from another TeletexString', () => {
        const original = new TeletexString({ value: 'Original Telex' })
        const copy = new TeletexString({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toEqual(original.toString())
    })

    test('should handle ASCII characters', () => {
        const asciiString = 'ASCII Telex Message 123'
        const teletexString = new TeletexString({ value: asciiString })

        expect(teletexString.toString()).toEqual(asciiString)

        // Verify UTF-8 encoding
        const expectedBytes = new TextEncoder().encode(asciiString)
        expect(teletexString.bytes).toEqual(expectedBytes)
    })

    test('should handle empty string', () => {
        const teletexString = new TeletexString({ value: '' })

        expect(teletexString.bytes.length).toEqual(0)
        expect(teletexString.toString()).toEqual('')
    })

    test('should convert to ASN.1 structure correctly', () => {
        const testString = 'Test Telex'
        const teletexString = new TeletexString({ value: testString })
        const asn1 = teletexString.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.TeletexString)

        // Verify the bytes are preserved in ASN.1
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        const expectedBytes = new TextEncoder().encode(testString)
        expect(valueHex).toEqual(expectedBytes)
    })

    test('should parse from ASN.1 structure correctly', () => {
        const testString = 'ASN1 Telex Test'
        const asn1 = new asn1js.TeletexString({ value: testString })

        const teletexString = TeletexString.fromAsn1(asn1)

        expect(teletexString).toBeInstanceOf(TeletexString)
        expect(teletexString.toString()).toEqual(testString)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => TeletexString.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected TeletexString',
        )
    })

    test('should convert to hex string', () => {
        const testCases = [
            { input: 'A', expected: '41' },
            { input: 'TEX', expected: '544558' },
            { input: '123', expected: '313233' },
            { input: '', expected: '' },
        ]

        for (const { input, expected } of testCases) {
            const teletexString = new TeletexString({ value: input })
            expect(teletexString.toHexString().toLowerCase()).toEqual(expected)
        }
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testStrings = [
            'Simple Telex',
            'Telex Message 123',
            '',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
        ]

        for (const testString of testStrings) {
            const original = new TeletexString({ value: testString })
            const asn1 = original.toAsn1()
            const decoded = TeletexString.fromAsn1(asn1)

            expect(decoded.toString()).toEqual(testString)
            expect(decoded.bytes).toEqual(original.bytes)
        }
    })

    test('should handle Teletex character set', () => {
        // Teletex supports standard ASCII characters
        const teletexChars =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz 0123456789'
        const teletexString = new TeletexString({ value: teletexChars })

        expect(teletexString.toString()).toEqual(teletexChars)

        // Test round-trip
        const asn1 = teletexString.toAsn1()
        const decoded = TeletexString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(teletexChars)
    })

    test('should handle basic punctuation', () => {
        const punctuationString = 'Hello, World! How are you?'
        const teletexString = new TeletexString({ value: punctuationString })

        expect(teletexString.toString()).toEqual(punctuationString)

        // Test round-trip
        const asn1 = teletexString.toAsn1()
        const decoded = TeletexString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(punctuationString)
    })
})
