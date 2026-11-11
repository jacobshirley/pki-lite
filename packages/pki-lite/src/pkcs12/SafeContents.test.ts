import { describe, test, expect } from 'vitest'
import { SafeContents } from './SafeContents.js'
import { SafeBag } from './SafeBag.js'
import { der } from '../core/PkiBase.js'

describe('SafeContents', () => {
    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = der.integer(42)
        expect(() => SafeContents.fromAsn1(notSequence)).toThrow(
            /SafeContents: expected SEQUENCE/,
        )
    })

    test('fromAsn1 should parse a valid Sequence of SafeBag', () => {
        // Create a proper SafeBag structure with required elements
        // SafeBag needs an ObjectIdentifier and a context-specific constructed tag
        const bagValue = der.constructed(0, [der.integer(1)])

        const safeBagAsn1_1 = der.sequence([
            der.oid('1.2.840.113549.1.12.10.1.1'), // keyBag OID
            bagValue,
        ])

        const safeBagAsn1_2 = der.sequence([
            der.oid('1.2.840.113549.1.12.10.1.2'), // pkcs8ShroudedKeyBag OID
            bagValue,
        ])

        const seq = der.sequence([safeBagAsn1_1, safeBagAsn1_2])
        const safeContents = SafeContents.fromAsn1(seq)
        expect(safeContents.length).toEqual(2)
        expect(safeContents[0]).toBeInstanceOf(SafeBag)
        expect(safeContents[1]).toBeInstanceOf(SafeBag)
    })

    test('fromDer should parse DER-encoded Sequence', () => {
        // Create a proper SafeBag structure with required elements
        const bagValue = der.constructed(0, [der.integer(7)])

        const safeBagAsn1 = der.sequence([
            der.oid('1.2.840.113549.1.12.10.1.1'), // keyBag OID
            bagValue,
        ])

        const seq = der.sequence([safeBagAsn1])
        const encoded = seq.encode()

        const safeContents = SafeContents.fromDer(new Uint8Array(encoded))
        expect(safeContents.length).toEqual(1)
        expect(safeContents[0]).toBeInstanceOf(SafeBag)
    })
})
