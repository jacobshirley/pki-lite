import { describe, expect, test } from 'vitest'
import { IA5String } from './IA5String.js'
import * as asn1js from 'asn1js'

describe('IA5String', () => {
    test('should create IA5String from string value', () => {
        const testString = 'hello@example.com'
        const ia5String = new IA5String({ value: testString })

        expect(ia5String).toBeInstanceOf(IA5String)
        expect(ia5String.toString()).toBe(testString)

        // Should encode as ASCII bytes
        const expectedBytes = new TextEncoder().encode(testString)
        expect(ia5String.bytes).toEqual(expectedBytes)
    })

    test('should create IA5String from Uint8Array', () => {
        const bytes = new Uint8Array([0x74, 0x65, 0x73, 0x74]) // "test"
        const ia5String = new IA5String({ value: bytes })

        expect(ia5String.bytes).toEqual(bytes)
        expect(ia5String.toString()).toBe('test')
    })

    test('should create IA5String from another IA5String', () => {
        const original = new IA5String({ value: 'original@test.com' })
        const copy = new IA5String({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toBe(original.toString())
    })

    test('should handle ASCII characters', () => {
        const asciiString = 'ABC123!@#$%'
        const ia5String = new IA5String({ value: asciiString })

        expect(ia5String.toString()).toBe(asciiString)

        // Verify ASCII encoding
        const expectedBytes = new TextEncoder().encode(asciiString)
        expect(ia5String.bytes).toEqual(expectedBytes)
    })

    test('should handle email addresses', () => {
        const emailString = 'user.name+tag@example.com'
        const ia5String = new IA5String({ value: emailString })

        expect(ia5String.toString()).toBe(emailString)
    })

    test('should handle empty string', () => {
        const ia5String = new IA5String({ value: '' })

        expect(ia5String.bytes.length).toBe(0)
        expect(ia5String.toString()).toBe('')
    })

    test('should convert to ASN.1 structure correctly', () => {
        const testString = 'test.ia5@domain.org'
        const ia5String = new IA5String({ value: testString })
        const asn1 = ia5String.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.IA5String)

        // Verify the bytes are preserved in ASN.1
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        const expectedBytes = new TextEncoder().encode(testString)
        expect(valueHex).toEqual(expectedBytes)
    })

    test('should parse from ASN.1 structure correctly', () => {
        const testString = 'asn1@test.example'
        const asn1 = new asn1js.IA5String({ value: testString })

        const ia5String = IA5String.fromAsn1(asn1)

        expect(ia5String).toBeInstanceOf(IA5String)
        expect(ia5String.toString()).toBe(testString)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => IA5String.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected IA5String',
        )
    })

    test('should convert to hex string', () => {
        const testCases = [
            { input: 'A', expected: '41' },
            { input: '@', expected: '40' },
            { input: 'test', expected: '74657374' },
            { input: '', expected: '' },
        ]

        for (const { input, expected } of testCases) {
            const ia5String = new IA5String({ value: input })
            expect(ia5String.toHexString().toLowerCase()).toBe(expected)
        }
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testStrings = [
            'simple',
            'email@domain.com',
            'complex+tag.name@sub.domain.org',
            '',
            '123456789',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        ]

        for (const testString of testStrings) {
            const original = new IA5String({ value: testString })
            const asn1 = original.toAsn1()
            const decoded = IA5String.fromAsn1(asn1)

            expect(decoded.toString()).toBe(testString)
            expect(decoded.bytes).toEqual(original.bytes)
        }
    })

    test('should handle printable ASCII characters', () => {
        // IA5String should handle all printable ASCII characters (0x20-0x7E)
        const printableChars = []
        for (let i = 0x20; i <= 0x7e; i++) {
            printableChars.push(String.fromCharCode(i))
        }
        const testString = printableChars.join('')

        const ia5String = new IA5String({ value: testString })
        expect(ia5String.toString()).toBe(testString)

        // Test round-trip
        const asn1 = ia5String.toAsn1()
        const decoded = IA5String.fromAsn1(asn1)
        expect(decoded.toString()).toBe(testString)
    })
})
