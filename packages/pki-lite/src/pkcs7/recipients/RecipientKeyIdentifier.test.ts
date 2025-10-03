import { assert, describe, expect, test } from 'vitest'
import { RecipientKeyIdentifier } from './RecipientKeyIdentifier.js'
import { KeyIdentifier } from './KeyIdentifier.js'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { asn1js } from '../../core/PkiBase.js'

describe('RecipientKeyIdentifier', () => {
    test('can be created with only subjectKeyIdentifier', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const rki = new RecipientKeyIdentifier({ subjectKeyIdentifier })
        expect(rki).toBeInstanceOf(RecipientKeyIdentifier)
        expect(rki.subjectKeyIdentifier.bytes).toEqual(keyId)
        expect(rki.date).toBeUndefined()
        expect(rki.other).toBeUndefined()
    })

    test('can be created with date', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const date = new Date()
        const rki = new RecipientKeyIdentifier({ subjectKeyIdentifier, date })
        expect(rki.date).toEqual(date)
    })

    test('can be created with other', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const other = new OtherKeyAttribute({ keyAttrId: '1.2.3.4' })
        const rki = new RecipientKeyIdentifier({
            subjectKeyIdentifier,
            other,
        })
        expect(rki.other).toEqual(other)
    })

    test('can be converted to ASN.1 with only subjectKeyIdentifier', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const rki = new RecipientKeyIdentifier({ subjectKeyIdentifier })
        const asn1 = rki.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(1)
        const keyIdBlock = asn1.valueBlock.value[0]
        assert(keyIdBlock instanceof asn1js.OctetString)
        expect(new Uint8Array(keyIdBlock.valueBlock.valueHexView)).toEqual(
            keyId,
        )
    })

    test('can be converted to ASN.1 with date and other', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const date = new Date()
        const other = new OtherKeyAttribute({ keyAttrId: '1.2.3.4' })
        const rki = new RecipientKeyIdentifier({
            subjectKeyIdentifier,
            date,
            other,
        })
        const asn1 = rki.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3)
        assert(asn1.valueBlock.value[1] instanceof asn1js.GeneralizedTime)
        assert(asn1.valueBlock.value[2] instanceof asn1js.Sequence)
    })

    test('can be parsed from ASN.1 with only subjectKeyIdentifier', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const rki = new RecipientKeyIdentifier({ subjectKeyIdentifier })
        const asn1 = rki.toAsn1()
        const parsed = RecipientKeyIdentifier.fromAsn1(asn1)
        expect(parsed).toBeInstanceOf(RecipientKeyIdentifier)
        expect(parsed.subjectKeyIdentifier.bytes).toEqual(keyId)
        expect(parsed.date).toBeUndefined()
        expect(parsed.other).toBeUndefined()
    })

    test('can be parsed from ASN.1 with date and other', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new KeyIdentifier({ bytes: keyId })
        const date = new Date(2023, 0, 1, 12, 0, 0)
        const other = new OtherKeyAttribute({ keyAttrId: '1.2.3.4' })
        const rki = new RecipientKeyIdentifier({
            subjectKeyIdentifier,
            date,
            other,
        })
        const asn1 = rki.toAsn1()
        const parsed = RecipientKeyIdentifier.fromAsn1(asn1)
        expect(parsed).toBeInstanceOf(RecipientKeyIdentifier)
        expect(parsed.subjectKeyIdentifier.bytes).toEqual(keyId)
        expect(parsed.date).toBeInstanceOf(Date)
        expect(parsed.other).toBeInstanceOf(OtherKeyAttribute)
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => RecipientKeyIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for RecipientKeyIdentifier',
        )
    })

    test('throws error on invalid ASN.1 structure element count', () => {
        const asn1 = new asn1js.Sequence({ value: [] })
        expect(() => RecipientKeyIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 1-3 elements, got 0',
        )
    })
})
