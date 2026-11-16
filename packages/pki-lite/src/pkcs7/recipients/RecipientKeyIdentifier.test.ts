import { assert, describe, expect, test } from 'vitest'
import { RecipientKeyIdentifier } from './RecipientKeyIdentifier.js'
import { KeyIdentifier } from './KeyIdentifier.js'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { der, UniversalTag } from '../../core/PkiBase.js'

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
        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(1)
        const keyIdBlock = asn1.children[0]
        assert(keyIdBlock.is(UniversalTag.OctetString))
        expect(keyIdBlock.bytes()).toEqual(keyId)
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
        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(3)
        assert(asn1.children[1]?.is(UniversalTag.GeneralizedTime))
        assert(asn1.children[2]?.is(UniversalTag.Sequence))
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
        const asn1 = der.integer(1)
        expect(() => RecipientKeyIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for RecipientKeyIdentifier',
        )
    })

    test('throws error on invalid ASN.1 structure element count', () => {
        const asn1 = der.sequence([])
        expect(() => RecipientKeyIdentifier.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 1-3 elements, got 0',
        )
    })

    test('encodes the date in whole seconds', () => {
        const der = new RecipientKeyIdentifier({
            subjectKeyIdentifier: new KeyIdentifier({
                bytes: new Uint8Array([1, 2, 3]),
            }),
            date: new Date('2026-11-13T08:03:23.166Z'),
        }).toDer()
        expect(String.fromCharCode(...der)).toContain('20261113080323Z')
        expect(String.fromCharCode(...der)).not.toContain('.166')
    })
})
