import { describe, expect, test } from 'vitest'
import { Any } from './Any.js'
import { Integer } from './Integer.js'
import * as asn1js from 'asn1js'

describe('Any', () => {
    test('should create Any with null value', () => {
        const any = new Any({ derBytes: null })

        expect(any).toBeInstanceOf(Any)
        expect(any.derBytes).toBeNull()
    })

    test('should create Any from Uint8Array<ArrayBuffer>', () => {
        const bytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x42]) // Simple ASN.1 sequence
        const any = new Any({ derBytes: bytes })

        expect(any.derBytes).toEqual(bytes)
    })

    test('should create Any from ArrayBuffer', () => {
        const arrayBuffer = new ArrayBuffer(5)
        const view = new Uint8Array(arrayBuffer)
        view.set([0x30, 0x03, 0x02, 0x01, 0x42])

        const any = new Any({ derBytes: arrayBuffer })

        expect(any.derBytes).toEqual(new Uint8Array(arrayBuffer))
    })

    test('should create Any from ASN.1 BaseBlock', () => {
        const asn1Integer = new asn1js.Integer({ value: 42 })
        const any = new Any({ derBytes: asn1Integer })

        expect(any.derBytes).toBeInstanceOf(Uint8Array<ArrayBuffer>)
        expect(any.derBytes!.length).toBeGreaterThan(0)
    })

    test('should create Any from string', () => {
        const testString = 'Hello World'
        const any = new Any({ derBytes: testString })

        expect(any.derBytes).toBeInstanceOf(Uint8Array<ArrayBuffer>)

        // Should be encoded as PrintableString
        const asn1 = any.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.PrintableString)
    })

    test('should create Any from number', () => {
        const testNumber = 42
        const any = new Any({ derBytes: testNumber })

        expect(any.derBytes).toBeInstanceOf(Uint8Array<ArrayBuffer>)

        // Should be encoded as Integer
        const asn1 = any.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Integer)
    })

    test('should create Any from another Any', () => {
        const original = new Any({ derBytes: new Uint8Array([1, 2, 3, 4]) })
        const copy = new Any({ derBytes: original })

        expect(copy.derBytes).toEqual(original.derBytes)
    })

    test('should create Any from PkiBase object', () => {
        const integer = new Integer({ value: 123 })
        const any = new Any({ derBytes: integer })

        expect(any.derBytes).toBeInstanceOf(Uint8Array<ArrayBuffer>)

        // Should preserve the integer value
        const asn1 = any.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Integer)
    })

    test('toAsn1 should return Null for null derBytes', () => {
        const any = new Any({ derBytes: null })
        const asn1 = any.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Null)
    })

    test('toAsn1 should parse DER bytes correctly', () => {
        // Create DER-encoded integer
        const integer = new Integer({ value: 42 })
        const derBytes = integer.toDer()

        const any = new Any({ derBytes: derBytes })
        const asn1 = any.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Integer)
        const integerValue = (asn1 as asn1js.Integer).valueBlock.valueDec
        expect(integerValue).toEqual(42)
    })

    test('asString should extract string values from different ASN.1 types', () => {
        // Test PrintableString
        const printableString = new asn1js.PrintableString({
            value: 'Test String',
        })
        const printableAny = new Any({ derBytes: printableString })
        expect(printableAny.asString()).toEqual('Test String')

        // Test UTF8String
        const utf8String = new asn1js.Utf8String({ value: 'UTF8 String' })
        const utf8Any = new Any({ derBytes: utf8String })
        expect(utf8Any.asString()).toEqual('UTF8 String')

        // Test OctetString
        const octetString = new asn1js.OctetString({
            valueHex: new TextEncoder().encode('Octet String'),
        })
        const octetAny = new Any({ derBytes: octetString })
        expect(octetAny.asString()).toEqual('Octet String')
    })

    test('asInteger should extract integer value', () => {
        const testNumber = 12345
        const any = new Any({ derBytes: testNumber })

        expect(any.asInteger()).toEqual(testNumber)
    })

    test('toHumanString should return NULL for null derBytes', () => {
        const any = new Any({ derBytes: null })

        expect(any.toHumanString()).toEqual('NULL')
    })

    test('toHumanString should return appropriate string representations', () => {
        // Test with string
        const stringAny = new Any({ derBytes: 'Test' })
        expect(stringAny.toHumanString()).toEqual('Test')

        // Test with number
        const numberAny = new Any({ derBytes: 42 })
        expect(numberAny.toHumanString()).toEqual('42')

        // Test with boolean true
        const booleanTrue = new asn1js.Boolean({ value: true })
        const booleanTrueAny = new Any({ derBytes: booleanTrue })
        expect(booleanTrueAny.toHumanString()).toEqual('TRUE')

        // Test with boolean false
        const booleanFalse = new asn1js.Boolean({ value: false })
        const booleanFalseAny = new Any({ derBytes: booleanFalse })
        expect(booleanFalseAny.toHumanString()).toEqual('FALSE')

        // Test with ObjectIdentifier
        const oid = new asn1js.ObjectIdentifier({ value: '1.2.3.4.5' })
        const oidAny = new Any({ derBytes: oid })
        expect(oidAny.toHumanString()).toEqual('1.2.3.4.5')
    })

    test('toHumanString should handle complex ASN.1 structures', () => {
        // Test with Sequence
        const sequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                new asn1js.Integer({ value: 2 }),
            ],
        })
        const sequenceAny = new Any({ derBytes: sequence })
        expect(sequenceAny.toHumanString()).toEqual('SEQUENCE (2 items)')

        // Test with Set
        const set = new asn1js.Set({
            value: [new asn1js.Integer({ value: 1 })],
        })
        const setAny = new Any({ derBytes: set })
        expect(setAny.toHumanString()).toEqual('SET (1 items)')

        // Test with BitString
        const bitString = new asn1js.BitString({
            valueHex: new Uint8Array([0xff, 0x00]),
        })
        const bitStringAny = new Any({ derBytes: bitString })
        expect(bitStringAny.toHumanString()).toContain('BIT STRING')
    })

    test('should handle empty Uint8Array<ArrayBuffer>', () => {
        const emptyBytes = new Uint8Array(0)
        const any = new Any({ derBytes: emptyBytes })

        expect(any.derBytes).toEqual(emptyBytes)
        expect(any.derBytes!.length).toEqual(0)
    })

    test('should handle large byte arrays', () => {
        const largeBytes = new Uint8Array(1000)
        largeBytes.fill(0x42)

        const any = new Any({ derBytes: largeBytes })

        expect(any.derBytes).toEqual(largeBytes)
        expect(any.derBytes!.length).toEqual(1000)
    })
})
