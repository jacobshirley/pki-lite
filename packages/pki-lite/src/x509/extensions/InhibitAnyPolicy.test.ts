import { describe, expect, test } from 'vitest'
import { InhibitAnyPolicy } from './InhibitAnyPolicy.js'
import { asn1js, derToAsn1 } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('InhibitAnyPolicy', () => {
    test('encodes the skip count as a plain INTEGER', () => {
        expect(hex(new InhibitAnyPolicy({ skipCerts: 0 }).toDer())).toBe(
            '020100',
        )
        expect(hex(new InhibitAnyPolicy({ skipCerts: 2 }).toDer())).toBe(
            '020102',
        )
    })

    test('round-trips through DER', () => {
        const der = new InhibitAnyPolicy({ skipCerts: 1000 }).toDer()
        const parsed = InhibitAnyPolicy.fromAsn1(derToAsn1(der))
        expect(parsed.skipCerts).toBe(1000)
        expect(hex(parsed.toDer())).toBe(hex(der))
    })

    test('rejects anything but an INTEGER', () => {
        expect(() =>
            InhibitAnyPolicy.fromAsn1(new asn1js.Sequence({ value: [] })),
        ).toThrow(Asn1ParseError)
    })
})
