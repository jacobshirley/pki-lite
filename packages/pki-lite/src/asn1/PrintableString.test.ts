import { describe, expect, test } from 'vitest'
import { PrintableString } from './PrintableString.js'
import { asn1js } from '../core/PkiBase.js'

describe('PrintableString', () => {
    test('should create PrintableString from string value', () => {
        const testString = 'Hello World'
        const printableString = new PrintableString({ value: testString })

        expect(printableString).toBeInstanceOf(PrintableString)
        expect(printableString.toString()).toEqual(testString)

        // Should encode as ASCII bytes
        const expectedBytes = new TextEncoder().encode(testString)
        expect(printableString.bytes).toEqual(expectedBytes)
    })

    test('should create PrintableString from Uint8Array<ArrayBuffer>', () => {
        const bytes = new Uint8Array([0x41, 0x42, 0x43]) // "ABC"
        const printableString = new PrintableString({ value: bytes })

        expect(printableString.bytes).toEqual(bytes)
        expect(printableString.toString()).toEqual('ABC')
    })

    test('should create PrintableString from another PrintableString', () => {
        const original = new PrintableString({ value: 'Original String' })
        const copy = new PrintableString({ value: original })

        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.toString()).toEqual(original.toString())
    })

    test('should handle printable characters', () => {
        // PrintableString typically supports: A-Z, a-z, 0-9, space, and some punctuation
        const printableChars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
        const printableString = new PrintableString({ value: printableChars })

        expect(printableString.toString()).toEqual(printableChars)

        // Verify ASCII encoding
        const expectedBytes = new TextEncoder().encode(printableChars)
        expect(printableString.bytes).toEqual(expectedBytes)
    })

    test('should handle organization names', () => {
        const orgName = 'Example Corp'
        const printableString = new PrintableString({ value: orgName })

        expect(printableString.toString()).toEqual(orgName)
    })

    test('should handle empty string', () => {
        const printableString = new PrintableString({ value: '' })

        expect(printableString.bytes.length).toEqual(0)
        expect(printableString.toString()).toEqual('')
    })

    test('should convert to ASN.1 structure correctly', () => {
        const testString = 'Test Printable'
        const printableString = new PrintableString({ value: testString })
        const asn1 = printableString.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.PrintableString)

        // Verify the bytes are preserved in ASN.1
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        const expectedBytes = new TextEncoder().encode(testString)
        expect(valueHex).toEqual(expectedBytes)
    })

    test('should parse from ASN.1 structure correctly', () => {
        const testString = 'ASN1 Test String'
        const asn1 = new asn1js.PrintableString({ value: testString })

        const printableString = PrintableString.fromAsn1(asn1)

        expect(printableString).toBeInstanceOf(PrintableString)
        expect(printableString.toString()).toEqual(testString)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => PrintableString.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected PrintableString',
        )
    })

    test('should convert to hex string', () => {
        const testCases = [
            { input: 'A', expected: '41' },
            { input: 'ABC', expected: '414243' },
            { input: '123', expected: '313233' },
            { input: '', expected: '' },
        ]

        for (const { input, expected } of testCases) {
            const printableString = new PrintableString({ value: input })
            expect(printableString.toHexString().toLowerCase()).toEqual(
                expected,
            )
        }
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testStrings = [
            'Simple',
            'Company Name Ltd',
            'Test 123',
            '',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            'Test (Company) Ltd.',
        ]

        for (const testString of testStrings) {
            const original = new PrintableString({ value: testString })
            const asn1 = original.toAsn1()
            const decoded = PrintableString.fromAsn1(asn1)

            expect(decoded.toString()).toEqual(testString)
            expect(decoded.bytes).toEqual(original.bytes)
        }
    })

    test('should handle common X.500 directory string characters', () => {
        // Characters commonly used in X.500 distinguished names
        const x500String = 'CN=John Doe, O=Example Corp, C=US'
        const printableString = new PrintableString({ value: x500String })

        expect(printableString.toString()).toEqual(x500String)

        // Test round-trip
        const asn1 = printableString.toAsn1()
        const decoded = PrintableString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(x500String)
    })

    test('should handle numbers and basic punctuation', () => {
        const numericString = '123-456-7890'
        const printableString = new PrintableString({ value: numericString })

        expect(printableString.toString()).toEqual(numericString)

        // Test round-trip
        const asn1 = printableString.toAsn1()
        const decoded = PrintableString.fromAsn1(asn1)
        expect(decoded.toString()).toEqual(numericString)
    })
})
