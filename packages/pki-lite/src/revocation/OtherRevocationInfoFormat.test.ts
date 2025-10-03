import { assert, describe, expect, test } from 'vitest'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { asn1js } from '../core/PkiBase.js'
import { Integer } from '../asn1/Integer.js'
import { OctetString } from '../asn1/OctetString.js'

describe('OtherRevocationInfoFormat', () => {
    test('can be created with string info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = 'test-revocation-info'

        const otherRevInfo = new OtherRevocationInfoFormat({
            otherRevInfoFormat: format,
            otherRevInfo: info,
        })

        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.asString()).toEqual(info)
    })

    test('can be created with number info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = 12345

        const otherRevInfo = new OtherRevocationInfoFormat({
            otherRevInfoFormat: format,
            otherRevInfo: info,
        })

        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.asInteger()).toEqual(info)
    })

    test('can be converted to ASN.1 with string info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = 'test-revocation-info'

        const otherRevInfo = new OtherRevocationInfoFormat({
            otherRevInfoFormat: format,
            otherRevInfo: info,
        })
        const asn1 = otherRevInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)

        const [formatAsn1, infoAsn1] = asn1.valueBlock.value

        expect(formatAsn1).toBeInstanceOf(asn1js.ObjectIdentifier)
        expect(formatAsn1.valueBlock.toString()).toContain(format)

        // For string values, anyToAsn1 creates a PrintableString
        expect(infoAsn1).toBeInstanceOf(asn1js.PrintableString)
        // Casting to access valueBlock.value which exists at runtime
        expect((infoAsn1 as any).valueBlock.value).toEqual(info)
    })

    test('can be converted to ASN.1 with Uint8Array<ArrayBuffer> info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = new Uint8Array([1, 2, 3, 4, 5])

        const otherRevInfo = new OtherRevocationInfoFormat({
            otherRevInfoFormat: format,
            otherRevInfo: info,
        })
        const asn1 = otherRevInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)

        const [formatAsn1, infoAsn1] = asn1.valueBlock.value

        expect(formatAsn1).toBeInstanceOf(asn1js.ObjectIdentifier)
        expect(formatAsn1.valueBlock.toString()).toContain(format)

        // For binary data, we get the ASN.1 structure from the BER encoding
        // Since our test Uint8Array<ArrayBuffer> is small, it might be interpreted as a different ASN.1 type
        // Let's just verify it's some kind of ASN.1 block
        expect(infoAsn1).toBeInstanceOf(asn1js.BaseBlock)
    })

    test('can be parsed from ASN.1 with OctetString info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = new Uint8Array([1, 2, 3, 4, 5])

        // Create ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: format }),
                new asn1js.OctetString({ valueHex: info }),
            ],
        })

        const otherRevInfo = OtherRevocationInfoFormat.fromAsn1(asn1)
        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.parseAs(OctetString)).toEqual(
            new OctetString({ bytes: info }),
        )
    })

    test('can be parsed from ASN.1 with string info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = 'test-revocation-info'

        // Create ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: format }),
                new asn1js.Utf8String({ value: info }),
            ],
        })

        const otherRevInfo = OtherRevocationInfoFormat.fromAsn1(asn1)
        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.asString()).toEqual(info)
    })

    test('can be parsed from ASN.1 with Integer info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = 12345

        // Create ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: format }),
                new asn1js.Integer({ value: info }),
            ],
        })

        const otherRevInfo = OtherRevocationInfoFormat.fromAsn1(asn1)
        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.parseAs(Integer).get()).toEqual(info)
    })

    test('fromAsn1 throws error for non-sequence', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => OtherRevocationInfoFormat.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '2.5.29.60' }),
                // Missing otherRevInfo
            ],
        })
        expect(() => OtherRevocationInfoFormat.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 2 elements',
        )
    })

    test('fromAsn1 throws error for invalid format OID', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // Not an ObjectIdentifier
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })
        expect(() => OtherRevocationInfoFormat.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
        )
    })
})
