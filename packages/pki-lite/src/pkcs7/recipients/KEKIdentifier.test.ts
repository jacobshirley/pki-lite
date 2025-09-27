import { assert, describe, expect, test } from 'vitest'
import { KEKIdentifier } from './KEKIdentifier.js'
import { asn1js } from '../../core/PkiBase.js'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'

describe('KEKIdentifier', () => {
    test('can be created', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const kekId = new KEKIdentifier({ keyIdentifier })
        expect(kekId).toBeInstanceOf(KEKIdentifier)
        expect(kekId.keyIdentifier).toEqual(keyIdentifier)
        expect(kekId.date).toBeUndefined()
        expect(kekId.other).toBeUndefined()
    })

    test('can be created with date', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const date = new Date()
        const kekId = new KEKIdentifier({ keyIdentifier, date })
        expect(kekId).toBeInstanceOf(KEKIdentifier)
        expect(kekId.keyIdentifier).toEqual(keyIdentifier)
        expect(kekId.date).toBe(date)
        expect(kekId.other).toBeUndefined()
    })

    test('can be created with other key attribute', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const other = new OtherKeyAttribute({
            keyAttrId: '2.16.840.1.101.3.4.1.42',
        })
        const kekId = new KEKIdentifier({ keyIdentifier, other })
        expect(kekId).toBeInstanceOf(KEKIdentifier)
        expect(kekId.keyIdentifier).toEqual(keyIdentifier)
        expect(kekId.date).toBeUndefined()
        expect(kekId.other).toBe(other)
    })

    test('can be created with all parameters', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const date = new Date()
        const other = new OtherKeyAttribute({
            keyAttrId: '2.16.840.1.101.3.4.1.42',
        })
        const kekId = new KEKIdentifier({ keyIdentifier, date, other })
        expect(kekId).toBeInstanceOf(KEKIdentifier)
        expect(kekId.keyIdentifier).toEqual(keyIdentifier)
        expect(kekId.date).toBe(date)
        expect(kekId.other).toBe(other)
    })

    test('can be converted to ASN.1 with only keyIdentifier', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const kekId = new KEKIdentifier({ keyIdentifier })
        const asn1 = kekId.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(1)

        const keyIdBlock = asn1.valueBlock.value[0]
        assert(keyIdBlock instanceof asn1js.OctetString)
        expect(new Uint8Array(keyIdBlock.valueBlock.valueHexView)).toEqual(
            keyIdentifier,
        )
    })

    test('can be converted to ASN.1 with date', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const date = new Date()
        const kekId = new KEKIdentifier({ keyIdentifier, date })
        const asn1 = kekId.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        const keyIdBlock = asn1.valueBlock.value[0]
        assert(keyIdBlock instanceof asn1js.OctetString)
        expect(new Uint8Array(keyIdBlock.valueBlock.valueHexView)).toEqual(
            keyIdentifier,
        )

        const dateBlock = asn1.valueBlock.value[1]
        assert(dateBlock instanceof asn1js.GeneralizedTime)
    })

    test('can be converted to ASN.1 with other', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const other = new OtherKeyAttribute({
            keyAttrId: '2.16.840.1.101.3.4.1.42',
        })
        const kekId = new KEKIdentifier({
            keyIdentifier: keyIdentifier,
            other: other,
        })
        const asn1 = kekId.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        const keyIdBlock = asn1.valueBlock.value[0]
        assert(keyIdBlock instanceof asn1js.OctetString)
        expect(new Uint8Array(keyIdBlock.valueBlock.valueHexView)).toEqual(
            keyIdentifier,
        )

        const otherBlock = asn1.valueBlock.value[1]
        assert(otherBlock instanceof asn1js.Sequence)
    })

    test('can be converted to ASN.1 with all parameters', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const date = new Date()
        const other = new OtherKeyAttribute({
            keyAttrId: '2.16.840.1.101.3.4.1.42',
        })
        const kekId = new KEKIdentifier({
            keyIdentifier: keyIdentifier,
            date: date,
            other: other,
        })
        const asn1 = kekId.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3)

        const keyIdBlock = asn1.valueBlock.value[0]
        assert(keyIdBlock instanceof asn1js.OctetString)
        expect(new Uint8Array(keyIdBlock.valueBlock.valueHexView)).toEqual(
            keyIdentifier,
        )

        const dateBlock = asn1.valueBlock.value[1]
        assert(dateBlock instanceof asn1js.GeneralizedTime)

        const otherBlock = asn1.valueBlock.value[2]
        assert(otherBlock instanceof asn1js.Sequence)
    })

    test('can be parsed from ASN.1 with only keyIdentifier', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const kekId = new KEKIdentifier({ keyIdentifier: keyIdentifier })
        const asn1 = kekId.toAsn1()
        const parsed = KEKIdentifier.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(KEKIdentifier)
        expect(parsed.keyIdentifier).toEqual(keyIdentifier)
        expect(parsed.date).toBeUndefined()
        expect(parsed.other).toBeUndefined()
    })

    test('can be parsed from ASN.1 with date', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        // Use fixed date to ensure equality check works
        const date = new Date(2023, 0, 1, 12, 0, 0)
        const kekId = new KEKIdentifier({
            keyIdentifier: keyIdentifier,
            date: date,
        })
        const asn1 = kekId.toAsn1()
        const parsed = KEKIdentifier.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(KEKIdentifier)
        expect(parsed.keyIdentifier).toEqual(keyIdentifier)
        expect(parsed.date).toBeInstanceOf(Date)
    })

    test('can be parsed from ASN.1 with other', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const other = new OtherKeyAttribute({
            keyAttrId: '2.16.840.1.101.3.4.1.42',
        })
        const kekId = new KEKIdentifier({
            keyIdentifier: keyIdentifier,
            other: other,
        })
        const asn1 = kekId.toAsn1()
        const parsed = KEKIdentifier.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(KEKIdentifier)
        expect(parsed.keyIdentifier).toEqual(keyIdentifier)
        expect(parsed.date).toBeUndefined()
        expect(parsed.other).toBeInstanceOf(OtherKeyAttribute)
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => KEKIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for KEKIdentifier',
        )
    })

    test('throws error on invalid ASN.1 structure element count', () => {
        const asn1 = new asn1js.Sequence({ value: [] })
        expect(() => KEKIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 1-3 elements, got 0',
        )
    })

    test('throws error on invalid keyIdentifier type', () => {
        const asn1 = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })
        expect(() => KEKIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected OctetString for keyIdentifier',
        )
    })
})
