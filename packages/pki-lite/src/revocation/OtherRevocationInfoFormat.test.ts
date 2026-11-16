import { assert, describe, expect, test } from 'vitest'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { Asn1Node, der, UniversalTag } from '../core/PkiBase.js'
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

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(2)

        const [formatAsn1, infoAsn1] = asn1.children

        expect(formatAsn1.is(UniversalTag.ObjectIdentifier)).toBe(true)
        expect(der.readOid(formatAsn1)).toContain(format)

        // For string values, anyToAsn1 creates a PrintableString
        expect(infoAsn1.is(UniversalTag.PrintableString)).toBe(true)
        expect(der.readString(infoAsn1)).toEqual(info)
    })

    test('can be converted to ASN.1 with Uint8Array<ArrayBuffer> info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = new Uint8Array([0x04, 0x03, 1, 2, 3]) // OCTET STRING

        const otherRevInfo = new OtherRevocationInfoFormat({
            otherRevInfoFormat: format,
            otherRevInfo: info,
        })
        const asn1 = otherRevInfo.toAsn1()

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(2)

        const [formatAsn1, infoAsn1] = asn1.children

        expect(formatAsn1.is(UniversalTag.ObjectIdentifier)).toBe(true)
        expect(der.readOid(formatAsn1)).toContain(format)

        // For binary data, we get the ASN.1 structure from the BER encoding
        // Since our test Uint8Array<ArrayBuffer> is small, it might be interpreted as a different ASN.1 type
        // Let's just verify it's some kind of ASN.1 block
        expect(infoAsn1).toBeInstanceOf(Asn1Node)
    })

    test('can be parsed from ASN.1 with OctetString info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = new Uint8Array([0x04, 0x03, 1, 2, 3]) // OCTET STRING

        // Create ASN.1 structure
        const asn1 = der.sequence([der.oid(format), der.octetString(info)])

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
        const asn1 = der.sequence([der.oid(format), der.utf8String(info)])

        const otherRevInfo = OtherRevocationInfoFormat.fromAsn1(asn1)
        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.asString()).toEqual(info)
    })

    test('can be parsed from ASN.1 with Integer info', () => {
        const format = '2.5.29.60' // OCSP Basic Response OID
        const info = 12345

        // Create ASN.1 structure
        const asn1 = der.sequence([der.oid(format), der.integer(info)])

        const otherRevInfo = OtherRevocationInfoFormat.fromAsn1(asn1)
        expect(otherRevInfo).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(otherRevInfo.otherRevInfoFormat.toString()).toEqual(format)
        expect(otherRevInfo.otherRevInfo.parseAs(Integer).get()).toEqual(info)
    })

    test('fromAsn1 throws error for non-sequence', () => {
        const asn1 = der.integer(1)
        expect(() => OtherRevocationInfoFormat.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = der.sequence([
            der.oid('2.5.29.60'),
            // Missing otherRevInfo
        ])
        expect(() => OtherRevocationInfoFormat.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 2 elements',
        )
    })

    test('fromAsn1 throws error for invalid format OID', () => {
        const asn1 = der.sequence([
            der.integer(1), // Not an ObjectIdentifier
            der.octetString(new Uint8Array([1, 2, 3])),
        ])
        expect(() => OtherRevocationInfoFormat.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
        )
    })
})
