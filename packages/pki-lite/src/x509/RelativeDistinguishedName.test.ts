import { assert, describe, expect, test } from 'vitest'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'

describe('RelativeDistinguishedName', () => {
    test('can be created empty', () => {
        const rdn = new RelativeDistinguishedName()
        expect(rdn).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdn.length).toEqual(0)
    })

    test('can be created with attributes', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)

        expect(rdn).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdn.length).toEqual(1)
        expect(rdn[0]).toEqual(cn)
    })

    test('can add attributes after creation', () => {
        const rdn = new RelativeDistinguishedName()
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })

        rdn.push(cn)

        expect(rdn.length).toEqual(1)
        expect(rdn[0]).toEqual(cn)
    })

    test('can be converted into ASN.1', () => {
        // Create a non-empty RDN to avoid any issues with empty arrays
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName()
        rdn.push(cn) // Add an item to make sure the array isn't empty

        const asn1 = rdn.toAsn1()

        assert(asn1 instanceof asn1js.Set)
        expect(asn1.valueBlock.value.length).toEqual(1)

        // The item should be a Sequence (the ASN.1 representation of AttributeTypeAndValue)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)
    })

    test('handles multiple attributes', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const o = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Test Org',
        })

        const rdn = new RelativeDistinguishedName()
        rdn.push(cn)
        rdn.push(ou)
        rdn.push(o)

        expect(rdn.length).toEqual(3)
        expect(rdn[0]).toEqual(cn)
        expect(rdn[1]).toEqual(ou)
        expect(rdn[2]).toEqual(o)
    })

    test('can be parsed from ASN.1', () => {
        // Create an ASN.1 SET containing AttributeTypeAndValue
        const cnValue = 'Test Common Name'
        const asn1 = new asn1js.Set({
            value: [
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: '2.5.4.3' }), // CN OID
                        new asn1js.PrintableString({ value: cnValue }),
                    ],
                }),
            ],
        })

        const rdn = RelativeDistinguishedName.fromAsn1(asn1)
        expect(rdn).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdn.length).toEqual(1)
        expect(rdn[0].type.toString()).toEqual('2.5.4.3')
        expect(rdn[0].shortName).toEqual('CN')
    })

    test('can be parsed from ASN.1 with multiple attributes', () => {
        // Create an ASN.1 SET with multiple AttributeTypeAndValue
        const asn1 = new asn1js.Set({
            value: [
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: '2.5.4.3' }), // CN OID
                        new asn1js.PrintableString({
                            value: 'Test Common Name',
                        }),
                    ],
                }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: '2.5.4.11' }), // OU OID
                        new asn1js.PrintableString({ value: 'Test Org Unit' }),
                    ],
                }),
            ],
        })

        const rdn = RelativeDistinguishedName.fromAsn1(asn1)
        expect(rdn).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdn.length).toEqual(2)
        expect(rdn[0].type.toString()).toEqual('2.5.4.3')
        expect(rdn[0].shortName).toEqual('CN')
        expect(rdn[1].type.toString()).toEqual('2.5.4.11')
        expect(rdn[1].shortName).toEqual('OU')
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a SET
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })

        expect(() => RelativeDistinguishedName.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SET',
        )
    })

    test('toString snapshot', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)
        expect(rdn.toString()).toMatchInlineSnapshot(`
          "[RelativeDistinguishedName] SET :
            SEQUENCE :
              OBJECT IDENTIFIER : 2.5.4.3
              PrintableString : 'Test Common Name'"
        `)
    })

    test('toString snapshot with multiple attributes', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const rdn = new RelativeDistinguishedName(cn, ou)
        expect(rdn.toString()).toMatchInlineSnapshot(`
          "[RelativeDistinguishedName] SET :
            SEQUENCE :
              OBJECT IDENTIFIER : 2.5.4.3
              PrintableString : 'Test Common Name'
            SEQUENCE :
              OBJECT IDENTIFIER : 2.5.4.11
              PrintableString : 'Test Org Unit'"
        `)
    })

    test('toPem snapshot', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)
        expect(rdn.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN RELATIVEDISTINGUISHEDNAME-----
          MRkwFwYDVQQDExBUZXN0IENvbW1vbiBOYW1l
          -----END RELATIVEDISTINGUISHEDNAME-----"
        `)
    })

    test('toPem snapshot with multiple attributes', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const rdn = new RelativeDistinguishedName(cn, ou)
        expect(rdn.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN RELATIVEDISTINGUISHEDNAME-----
          MS8wFwYDVQQDExBUZXN0IENvbW1vbiBOYW1lMBQGA1UECxMNVGVzdCBPcmcgVW5pdA==
          -----END RELATIVEDISTINGUISHEDNAME-----"
        `)
    })
})
