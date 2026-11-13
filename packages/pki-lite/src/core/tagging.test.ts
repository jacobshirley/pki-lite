import { describe, expect, test } from 'vitest'
import {
    implicitSequence,
    implicitSequenceOf,
    implicitTag,
    isContextTag,
} from './tagging.js'
import { asn1js, derToAsn1 } from './PkiBase.js'

const hex = (b: ArrayBuffer | Uint8Array) =>
    Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join(
        '',
    )

describe('implicitTag', () => {
    test('replaces the tag of a primitive with [n], keeping its content', () => {
        const block = implicitTag(new asn1js.Integer({ value: 5 }), 0)
        expect(hex(block.toBER(false))).toBe('800105')
    })

    test('keeps a constructed block constructed', () => {
        const block = implicitTag(
            new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] }),
            1,
        )
        // [1] IMPLICIT SEQUENCE { INTEGER 1 }: A1, not A1 wrapping a 30
        expect(hex(block.toBER(false))).toBe('a103020101')
    })

    test('works for higher tag numbers', () => {
        const block = implicitTag(
            new asn1js.OctetString({ valueHex: new Uint8Array([0xaa]) }),
            6,
        )
        expect(hex(block.toBER(false))).toBe('8601aa')
    })

    test('returns the same block, re-tagged in place', () => {
        const integer = new asn1js.Integer({ value: 7 })
        expect(implicitTag(integer, 2)).toBe(integer)
        expect(integer.idBlock.tagClass).toBe(3)
        expect(integer.idBlock.tagNumber).toBe(2)
    })
})

describe('isContextTag', () => {
    test('matches the context-specific tag number only', () => {
        const tagged = implicitTag(new asn1js.Integer({ value: 1 }), 3)
        expect(isContextTag(tagged, 3)).toBe(true)
        expect(isContextTag(tagged, 0)).toBe(false)
    })

    test('does not match universal tags with the same number', () => {
        // BOOLEAN is UNIVERSAL 1, INTEGER is UNIVERSAL 2
        expect(isContextTag(new asn1js.Boolean({ value: true }), 1)).toBe(false)
        expect(isContextTag(new asn1js.Integer({ value: 1 }), 2)).toBe(false)
    })

    test('recognises parsed implicit and explicit tags', () => {
        expect(
            isContextTag(derToAsn1(new Uint8Array([0x80, 0x01, 0x05])), 0),
        ).toBe(true)
        expect(
            isContextTag(
                derToAsn1(new Uint8Array([0xa2, 0x03, 0x02, 0x01, 0x05])),
                2,
            ),
        ).toBe(true)
    })
})

describe('implicitSequence', () => {
    test('reads a parsed [n] IMPLICIT SEQUENCE back as a SEQUENCE', () => {
        // [3] IMPLICIT SEQUENCE { INTEGER 5 }
        const parsed = derToAsn1(new Uint8Array([0xa3, 0x03, 0x02, 0x01, 0x05]))
        const seq = implicitSequence(parsed)
        expect(seq).toBeInstanceOf(asn1js.Sequence)
        expect(hex(seq.toBER(false))).toBe('3003020105')
    })

    test('rejects a primitive', () => {
        expect(() =>
            implicitSequence(derToAsn1(new Uint8Array([0x83, 0x01, 0x05]))),
        ).toThrow('expected a constructed value')
    })
})

describe('implicitSequenceOf', () => {
    // SEQUENCE { INTEGER 1 } and SEQUENCE { INTEGER 2 }
    const items = [
        new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] }),
        new asn1js.Sequence({ value: [new asn1js.Integer({ value: 2 })] }),
    ]
    const parse = (block: asn1js.BaseBlock) =>
        implicitSequenceOf(derToAsn1(new Uint8Array(block.toBER(false))))

    test('reads the elements of an IMPLICIT [n] SEQUENCE OF', () => {
        const tagged = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value: items,
        })
        expect(hex(parse(tagged).toBER(false))).toBe('300a30030201013003020102')
    })

    test('accepts the explicitly tagged form', () => {
        const tagged = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value: [new asn1js.Sequence({ value: items })],
        })
        expect(hex(parse(tagged).toBER(false))).toBe('300a30030201013003020102')
    })

    test('reads a single element that is not a SEQUENCE OF SEQUENCEs as itself', () => {
        const tagged = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value: [items[0]],
        })
        expect(hex(parse(tagged).toBER(false))).toBe('30053003020101')
    })
})
