import { describe, expect, test } from 'vitest'
import { implicitTag, isContextTag } from './tagging.js'
import { der, derToAsn1 } from './PkiBase.js'

const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('implicitTag', () => {
    test('replaces the tag of a primitive with [n], keeping its content', () => {
        const block = implicitTag(der.integer(5), 0)
        expect(hex(block.encode())).toBe('800105')
    })

    test('keeps a constructed block constructed', () => {
        const block = implicitTag(der.sequence([der.integer(1)]), 1)
        // [1] IMPLICIT SEQUENCE { INTEGER 1 }: A1, not A1 wrapping a 30
        expect(hex(block.encode())).toBe('a103020101')
    })

    test('works for higher tag numbers', () => {
        const block = implicitTag(der.octetString(new Uint8Array([0xaa])), 6)
        expect(hex(block.encode())).toBe('8601aa')
    })

    test('returns a new node, leaving the input untouched', () => {
        const integer = der.integer(7)
        const tagged = implicitTag(integer, 2)
        expect(tagged).not.toBe(integer)
        expect(hex(integer.encode())).toBe('020107')
        expect(tagged.isContext(2)).toBe(true)
    })
})

describe('isContextTag', () => {
    test('matches the context-specific tag number only', () => {
        const tagged = implicitTag(der.integer(1), 3)
        expect(isContextTag(tagged, 3)).toBe(true)
        expect(isContextTag(tagged, 0)).toBe(false)
    })

    test('does not match universal tags with the same number', () => {
        // BOOLEAN is UNIVERSAL 1, INTEGER is UNIVERSAL 2
        expect(isContextTag(der.boolean(true), 1)).toBe(false)
        expect(isContextTag(der.integer(1), 2)).toBe(false)
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
