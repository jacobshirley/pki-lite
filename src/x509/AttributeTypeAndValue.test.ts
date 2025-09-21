import { assert, describe, expect, test } from 'vitest'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js, asn1ToDer } from '../core/PkiBase.js'

describe('AttributeTypeAndValue', () => {
    test('can be created', () => {
        const atv = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        }) // CN
        expect(atv).toBeInstanceOf(AttributeTypeAndValue)
        expect(atv.type.toString()).toBe('2.5.4.3')
        expect(atv.value.asString()).toBe('Test Common Name')
    })

    test('can be converted into ASN.1', () => {
        const atv = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const asn1 = atv.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.ObjectIdentifier)
        assert(asn1.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)
        // The toString() method includes "OBJECT IDENTIFIER : " prefix
        expect(asn1.valueBlock.value[0].toString()).toBe(
            'OBJECT IDENTIFIER : 2.5.4.3',
        )

        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.PrintableString)
        assert(asn1.valueBlock.value[1] instanceof asn1js.PrintableString)
        expect(asn1.valueBlock.value[1].valueBlock.value).toBe(
            'Test Common Name',
        )
    })

    test('can convert common OIDs to shortnames', () => {
        // This test would only work if shortName getter is properly implemented
        // Currently there's a recursive reference in the getter that needs fixing
        const cnAtv = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const ouAtv = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })

        // Skip assertion since there's an issue with the shortName getter
        expect(cnAtv.shortName).toBe('CN')
        expect(ouAtv.shortName).toBe('OU')
    })

    test('toHumanString() returns formatted representation', () => {
        // Skip assertion since it depends on shortName getter which has an issue
        const atv = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        expect(atv.toHumanString()).toBe('CN=Test Common Name')
    })

    test('handles different attribute types', () => {
        const countryAtv = new AttributeTypeAndValue({
            type: '2.5.4.6',
            value: 'US',
        })
        const orgAtv = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Example Org',
        })

        expect(countryAtv.type.toString()).toBe('2.5.4.6')
        expect(countryAtv.value.asString()).toBe('US')

        expect(orgAtv.type.toString()).toBe('2.5.4.10')
        expect(orgAtv.value.asString()).toBe('Example Org')
    })

    test('can be converted from ASN.1', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '2.5.4.3' }),
                new asn1js.PrintableString({ value: 'Test Common Name' }),
            ],
        })

        const atv = AttributeTypeAndValue.fromAsn1(asn1)
        expect(atv).toBeInstanceOf(AttributeTypeAndValue)
        expect(atv.type.toString()).toBe('2.5.4.3')
        expect(atv.value.asString()).toEqual('Test Common Name')
    })

    test('toHumanString snapshot', () => {
        const atv = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        expect(atv.toHumanString()).toMatchInlineSnapshot(
            `"CN=Test Common Name"`,
        )
    })

    test('toPem snapshot', () => {
        const atv = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        expect(atv.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ATTRIBUTETYPEANDVALUE-----
          MBcGA1UEAxMQVGVzdCBDb21tb24gTmFtZQ==
          -----END ATTRIBUTETYPEANDVALUE-----"
        `)
    })

    test('toString snapshot for different attribute types', () => {
        const countryAtv = new AttributeTypeAndValue({
            type: '2.5.4.6',
            value: 'US',
        })
        expect(countryAtv.toString()).toMatchInlineSnapshot(`
          "[AttributeTypeAndValue] SEQUENCE :
            OBJECT IDENTIFIER : 2.5.4.6
            PrintableString : 'US'"
        `)
    })

    test('toPem snapshot for different attribute types', () => {
        const orgAtv = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Example Org',
        })
        expect(orgAtv.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ATTRIBUTETYPEANDVALUE-----
          MBIGA1UEChMLRXhhbXBsZSBPcmc=
          -----END ATTRIBUTETYPEANDVALUE-----"
        `)
    })
})
