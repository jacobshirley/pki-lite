import { assert, describe, expect, test } from 'vitest'
import { KeyIdentifier } from './KeyIdentifier.js'
import { der, UniversalTag } from '../../core/PkiBase.js'

describe('KeyIdentifier', () => {
    test('can be created from Uint8Array<ArrayBuffer>', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const keyIdentifier = new KeyIdentifier({ bytes: keyId })

        expect(keyIdentifier).toBeInstanceOf(KeyIdentifier)
        expect(keyIdentifier.bytes).toEqual(keyId)
    })

    test('can be created from string', () => {
        const keyIdStr = 'test-key-id'
        const keyIdentifier = new KeyIdentifier({ bytes: keyIdStr })

        expect(keyIdentifier).toBeInstanceOf(KeyIdentifier)
        expect(keyIdentifier.bytes).toEqual(new TextEncoder().encode(keyIdStr))
    })

    test('can be created from another KeyIdentifier', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const keyIdentifier1 = new KeyIdentifier({ bytes: keyId })
        const keyIdentifier2 = new KeyIdentifier({ bytes: keyIdentifier1 })

        expect(keyIdentifier2).toBeInstanceOf(KeyIdentifier)
        expect(keyIdentifier2.bytes).toEqual(keyId)
    })

    test('can be converted to ASN.1', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const keyIdentifier = new KeyIdentifier({ bytes: keyId })
        const asn1 = keyIdentifier.toAsn1()

        assert(asn1.is(UniversalTag.OctetString))
        expect(asn1.bytes()).toEqual(keyId)
    })

    test('can be parsed from ASN.1', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const asn1 = der.octetString(keyId)
        const keyIdentifier = KeyIdentifier.fromAsn1(asn1)

        expect(keyIdentifier).toBeInstanceOf(KeyIdentifier)
        expect(keyIdentifier.bytes).toEqual(keyId)
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = der.integer(1)
        expect(() => KeyIdentifier.fromAsn1(asn1)).toThrow(
            /Invalid ASN.1 structure/,
        )
    })
})
