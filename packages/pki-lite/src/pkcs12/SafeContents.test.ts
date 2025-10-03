import { describe, test, expect } from 'vitest'
import { SafeContents } from './SafeContents.js'
import { SafeBag } from './SafeBag.js'
import { asn1js } from '../core/PkiBase.js'

describe('SafeContents', () => {
    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = new asn1js.Integer({ value: 42 })
        expect(() => SafeContents.fromAsn1(notSequence)).toThrow(
            /SafeContents: expected SEQUENCE/,
        )
    })

    test('fromAsn1 should parse a valid Sequence of SafeBag', () => {
        // Create a proper SafeBag structure with required elements
        // SafeBag needs an ObjectIdentifier and a context-specific constructed tag
        const bagValue = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 0 },
            value: [new asn1js.Integer({ value: 1 })],
        })

        const safeBagAsn1_1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({
                    value: '1.2.840.113549.1.12.10.1.1',
                }), // keyBag OID
                bagValue,
            ],
        })

        const safeBagAsn1_2 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({
                    value: '1.2.840.113549.1.12.10.1.2',
                }), // pkcs8ShroudedKeyBag OID
                bagValue,
            ],
        })

        const seq = new asn1js.Sequence({
            value: [safeBagAsn1_1, safeBagAsn1_2],
        })
        const safeContents = SafeContents.fromAsn1(seq)
        expect(safeContents.length).toEqual(2)
        expect(safeContents[0]).toBeInstanceOf(SafeBag)
        expect(safeContents[1]).toBeInstanceOf(SafeBag)
    })

    test('fromDer should parse DER-encoded Sequence', () => {
        // Create a proper SafeBag structure with required elements
        const bagValue = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 0 },
            value: [new asn1js.Integer({ value: 7 })],
        })

        const safeBagAsn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({
                    value: '1.2.840.113549.1.12.10.1.1',
                }), // keyBag OID
                bagValue,
            ],
        })

        const seq = new asn1js.Sequence({
            value: [safeBagAsn1],
        })
        const der = seq.toBER(false)

        const safeContents = SafeContents.fromDer(new Uint8Array(der))
        expect(safeContents.length).toEqual(1)
        expect(safeContents[0]).toBeInstanceOf(SafeBag)
    })
})
