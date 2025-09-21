import { assert, describe, expect, test } from 'vitest'
import { Extension } from './Extension.js'
import { asn1js, ObjectIdentifierString } from '../core/PkiBase.js'
import { BitString } from '../asn1/BitString.js'

describe('Extension', () => {
    test('can be created', () => {
        const extensionId: ObjectIdentifierString = '2.5.29.15' // keyUsage
        const critical = true
        const value = new BitString({ value: 'Test Extension' })

        const extension = new Extension({
            extnID: extensionId,
            critical: critical,
            extnValue: value,
        })

        expect(extension).toBeInstanceOf(Extension)
        expect(extension.extnID.toString()).toBe(extensionId)
        expect(extension.critical).toBe(critical)
        expect(extension.extnValue.parseAs(BitString)).toEqual(value)
    })

    test('can be created with non-critical extension', () => {
        const extensionId: ObjectIdentifierString = '2.5.29.14' // subjectKeyIdentifier
        const critical = false
        const value = true

        const extension = new Extension({
            extnID: extensionId,
            critical: critical,
            extnValue: value,
        })

        expect(extension).toBeInstanceOf(Extension)
        expect(extension.extnID.toString()).toBe(extensionId)
        expect(extension.critical).toBe(critical)
        expect(extension.extnValue.toDer()).toEqual(
            new Uint8Array(
                new asn1js.OctetString({
                    valueHex: new asn1js.Boolean({ value: value }).toBER(false),
                }).toBER(false),
            ),
        )
    })

    test('can be converted to ASN.1', () => {
        const extensionId: ObjectIdentifierString = '2.5.29.15' // keyUsage
        const critical = true
        const value = new Uint8Array([1, 2, 3, 4, 5])

        const extension = new Extension({
            extnID: extensionId,
            critical: critical,
            extnValue: value,
        })
        const asn1 = extension.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3) // extnID, critical, extnValue

        const [idBlock, criticalBlock, valueBlock] = asn1.valueBlock.value

        expect(idBlock).toBeInstanceOf(asn1js.ObjectIdentifier)
        // OID is represented as an array internally, so we just check it's an ObjectIdentifier

        expect(criticalBlock).toBeInstanceOf(asn1js.Boolean)
        expect((criticalBlock as asn1js.Boolean).valueBlock.value).toBe(true)

        expect(valueBlock).toBeInstanceOf(asn1js.OctetString)
        expect(extension.toString()).toMatchInlineSnapshot(`
          "[Extension] SEQUENCE :
            OBJECT IDENTIFIER : 2.5.29.15
            BOOLEAN: TRUE
            OCTET STRING : 01020304"
        `)
    })

    test('can be converted to ASN.1 with non-critical extension', () => {
        const extensionId: ObjectIdentifierString = '2.5.29.14' // subjectKeyIdentifier
        const critical = false
        const value = new BitString({ value: 'Non-critical value' }).toDer()

        const extension = new Extension({
            extnID: extensionId,
            critical: critical,
            extnValue: value,
        })
        const asn1 = extension.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2) // extnID, extnValue (no critical flag)

        const [idBlock, valueBlock] = asn1.valueBlock.value

        expect(idBlock).toBeInstanceOf(asn1js.ObjectIdentifier)
        // OID is represented as an array internally, so we just check it's an ObjectIdentifier

        expect(valueBlock).toBeInstanceOf(asn1js.OctetString)
        expect(
            (valueBlock as asn1js.OctetString).valueBlock.valueHexView,
        ).toEqual(value)
    })

    test('can be converted to and from ASN.1', () => {
        const extension = new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: new BitString({ value: 'Test Extension' }),
        })
        const asn1 = extension.toAsn1()
        const parsed = Extension.fromAsn1(asn1)

        expect(parsed).toEqual(extension)
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a sequence
        const asn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => Extension.fromAsn1(asn1)).toThrow('Expected Sequence')
    })

    test('throws an error when extnID is not an ObjectIdentifier', () => {
        // Create an ASN.1 sequence with invalid extnID field
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
                new asn1js.OctetString({ valueHex: new Uint8Array([4, 5, 6]) }),
            ],
        })

        expect(() => Extension.fromAsn1(asn1)).toThrow(
            'Expected ObjectIdentifier for extnID',
        )
    })

    test('throws an error when critical flag is not a Boolean', () => {
        // Create an ASN.1 sequence with invalid critical field
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '2.5.29.15' }),
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
                new asn1js.OctetString({ valueHex: new Uint8Array([4, 5, 6]) }),
            ],
        })

        expect(() => Extension.fromAsn1(asn1)).toThrow(
            'Expected Boolean for critical',
        )
    })

    test('throws an error when extnValue is not an OctetString', () => {
        // Create an ASN.1 sequence with invalid extnValue field
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '2.5.29.15' }),
                new asn1js.Boolean({ value: true }),
                new asn1js.ObjectIdentifier({ value: '1.2.3.4' }),
            ],
        })

        expect(() => Extension.fromAsn1(asn1)).toThrow(
            'Expected OctetString for extnValue',
        )
    })

    test('toString snapshot', () => {
        const extension = new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: new Uint8Array([1, 2, 3, 4, 5]),
        })
        expect(extension.toString()).toMatchInlineSnapshot(`
          "[Extension] SEQUENCE :
            OBJECT IDENTIFIER : 2.5.29.15
            BOOLEAN: TRUE
            OCTET STRING : 01020304"
        `)
    })

    test('toString snapshot non-critical', () => {
        const extension = new Extension({
            extnID: '2.5.29.14',
            critical: false,
            extnValue: new Uint8Array([5, 4, 3, 2, 1]),
        })
        expect(extension.toString()).toMatchInlineSnapshot(`
          "[Extension] SEQUENCE :
            OBJECT IDENTIFIER : 2.5.29.14
            OCTET STRING : 0500"
        `)
    })

    test('toPem snapshot', () => {
        const extension = new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: new Uint8Array([1, 2, 3, 4, 5]),
        })
        expect(extension.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN EXTENSION-----
          MA4GA1UdDwEB/wQEAQIDBA==
          -----END EXTENSION-----"
        `)
    })

    test('toPem snapshot non-critical', () => {
        const extension = new Extension({
            extnID: '2.5.29.14',
            critical: false,
            extnValue: new Uint8Array([5, 4, 3, 2, 1]),
        })
        expect(extension.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN EXTENSION-----
          MAkGA1UdDgQCBQA=
          -----END EXTENSION-----"
        `)
    })
})
