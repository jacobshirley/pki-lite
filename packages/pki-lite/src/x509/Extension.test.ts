import { assert, describe, expect, test } from 'vitest'
import { Extension } from './Extension.js'
import { der, ObjectIdentifierString, UniversalTag } from '../core/PkiBase.js'
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
        expect(extension.extnID.toString()).toEqual(extensionId)
        expect(extension.critical).toEqual(critical)
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
        expect(extension.extnID.toString()).toEqual(extensionId)
        expect(extension.critical).toEqual(critical)
        expect(extension.extnValue.toDer()).toEqual(
            new Uint8Array(
                der.octetString(der.boolean(value).encode()).encode(),
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

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(3) // extnID, critical, extnValue

        const [idBlock, criticalBlock, valueBlock] = asn1.children

        expect(idBlock.is(UniversalTag.ObjectIdentifier)).toBe(true)
        // OID is represented as an array internally, so we just check it's an ObjectIdentifier

        expect(criticalBlock.is(UniversalTag.Boolean)).toBe(true)
        expect(der.readBoolean(criticalBlock)).toEqual(true)

        expect(valueBlock.is(UniversalTag.OctetString)).toBe(true)
        expect(extension.toString()).toMatchInlineSnapshot(`
          "[Extension] SEQUENCE :
            OBJECT IDENTIFIER : 2.5.29.15
            BOOLEAN: TRUE
            OCTET STRING : 0102030405"
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

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(2) // extnID, extnValue (no critical flag)

        const [idBlock, valueBlock] = asn1.children

        expect(idBlock.is(UniversalTag.ObjectIdentifier)).toBe(true)
        // OID is represented as an array internally, so we just check it's an ObjectIdentifier

        expect(valueBlock.is(UniversalTag.OctetString)).toBe(true)
        expect(valueBlock.bytes()).toEqual(value)
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
        const asn1 = der.octetString(new Uint8Array([1, 2, 3]))

        expect(() => Extension.fromAsn1(asn1)).toThrow('Expected Sequence')
    })

    test('throws an error when extnID is not an ObjectIdentifier', () => {
        // Create an ASN.1 sequence with invalid extnID field
        const asn1 = der.sequence([
            der.octetString(new Uint8Array([1, 2, 3])),
            der.octetString(new Uint8Array([4, 5, 6])),
        ])

        expect(() => Extension.fromAsn1(asn1)).toThrow(
            'Expected ObjectIdentifier for extnID',
        )
    })

    test('throws an error when critical flag is not a Boolean', () => {
        // Create an ASN.1 sequence with invalid critical field
        const asn1 = der.sequence([
            der.oid('2.5.29.15'),
            der.octetString(new Uint8Array([1, 2, 3])),
            der.octetString(new Uint8Array([4, 5, 6])),
        ])

        expect(() => Extension.fromAsn1(asn1)).toThrow(
            'Expected Boolean for critical',
        )
    })

    test('throws an error when extnValue is not an OctetString', () => {
        // Create an ASN.1 sequence with invalid extnValue field
        const asn1 = der.sequence([
            der.oid('2.5.29.15'),
            der.boolean(true),
            der.oid('1.2.3.4'),
        ])

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
            OCTET STRING : 0102030405"
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
            OCTET STRING : 0504030201"
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
          MA8GA1UdDwEB/wQFAQIDBAU=
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
          MAwGA1UdDgQFBQQDAgE=
          -----END EXTENSION-----"
        `)
    })

    test('authorityKeyIdentifier writes an AuthorityKeyIdentifier SEQUENCE, not a bare OCTET STRING', () => {
        const extension = Extension.authorityKeyIdentifier(
            new Uint8Array([1, 2, 3, 4]),
        )
        // SEQUENCE { [0] 01020304 }
        expect(
            Array.from(extension.extnValue.bytes, (b) =>
                b.toString(16).padStart(2, '0'),
            ).join(''),
        ).toBe('300680040102' + '0304')
    })
})
