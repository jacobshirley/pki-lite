import { describe, expect, test } from 'vitest'
import { Asn1ParseError } from '../errors/Asn1ParseError.js'
import { Asn1Node } from './Asn1Node.js'
import * as der from './builders.js'
import * as read from './readers.js'

const hex = (s: string) =>
    Asn1Node.parse(
        new Uint8Array(
            s
                .replace(/\s+/g, '')
                .match(/../g)!
                .map((b) => parseInt(b, 16)),
        ),
    )
const time = (tag: number, s: string) =>
    new Asn1Node({ tag, content: new TextEncoder().encode(s) })

describe('readers', () => {
    test('readBoolean', () => {
        expect(read.readBoolean(der.boolean(true))).toBe(true)
        expect(read.readBoolean(der.boolean(false))).toBe(false)
        expect(read.readBoolean(hex('01 01 01'))).toBe(true) // BER
        expect(() => read.readBoolean(hex('01 02 00 00'))).toThrow(
            Asn1ParseError,
        )
        expect(() => read.readBoolean(der.integer(1))).toThrow(Asn1ParseError)
    })

    test('readNull', () => {
        expect(read.readNull(der.nullValue())).toBeNull()
        expect(() => read.readNull(hex('05 01 00'))).toThrow(Asn1ParseError)
    })

    test.each([0n, 1n, 127n, 128n, -1n, -128n, -129n, 2n ** 64n, -(2n ** 70n)])(
        'integer %d round-trips',
        (n) => {
            expect(read.readBigInt(der.integer(n))).toBe(n)
        },
    )

    test('readNumber and readIntegerBytes', () => {
        expect(read.readNumber(der.integer(-300))).toBe(-300)
        expect(read.readIntegerBytes(der.integer(128))).toEqual(
            new Uint8Array([0, 128]),
        )
        expect(() => read.readNumber(der.integer(2n ** 60n))).toThrow(
            Asn1ParseError,
        )
        expect(() => read.readIntegerBytes(hex('02 00'))).toThrow(
            Asn1ParseError,
        )
    })

    test('readEnumerated', () => {
        expect(read.readEnumerated(der.enumerated(3))).toBe(3)
        expect(() => read.readEnumerated(der.integer(3))).toThrow(
            Asn1ParseError,
        )
    })

    test.each([
        '1.2.840.113549.1.1.11',
        '2.999.3',
        '0.9.2342.19200300.100.1.25',
        '2.5.4.3',
        '1.2.18446744073709551617',
    ])('readOid %s round-trips', (oid) => {
        expect(read.readOid(der.oid(oid))).toBe(oid)
    })

    test('readOid rejects malformed content', () => {
        expect(() => read.readOid(hex('06 00'))).toThrow(Asn1ParseError)
        expect(() => read.readOid(hex('06 01 81'))).toThrow(Asn1ParseError)
        expect(() => read.readOid(hex('06 03 2a 80 01'))).toThrow(
            Asn1ParseError,
        )
    })

    test('readOctetString flattens constructed BER strings', () => {
        expect(
            read.readOctetString(hex('24 80 04 01 aa 04 01 bb 00 00')),
        ).toEqual(new Uint8Array([0xaa, 0xbb]))
    })

    test('readBitString', () => {
        expect(
            read.readBitString(der.bitString(new Uint8Array([0xa0]), 5)),
        ).toEqual({
            bytes: new Uint8Array([0xa0]),
            unusedBits: 5,
        })
        expect(
            read.readBitString(hex('23 80 03 02 00 aa 03 02 04 b0 00 00')),
        ).toEqual({
            bytes: new Uint8Array([0xaa, 0xb0]),
            unusedBits: 4,
        })
        expect(() => read.readBitString(hex('03 00'))).toThrow(Asn1ParseError)
        expect(() => read.readBitString(hex('03 01 01'))).toThrow(
            Asn1ParseError,
        )
        expect(() => read.readBitString(hex('03 02 08 00'))).toThrow(
            Asn1ParseError,
        )
    })

    test('readNamedBits', () => {
        expect(read.readNamedBits(der.namedBits([true, false, true]))).toEqual([
            true,
            false,
            true,
        ])
        expect(read.readNamedBits(der.namedBits([]))).toEqual([])
    })

    test.each([
        ['utf8', der.utf8String('héllo ✓'), 'héllo ✓'],
        ['printable', der.printableString('Test CA'), 'Test CA'],
        ['ia5', der.ia5String('a@b.c'), 'a@b.c'],
        ['visible', der.visibleString('hi'), 'hi'],
        ['teletex', der.teletexString('é'), 'é'],
        ['bmp', der.bmpString('Zoë'), 'Zoë'],
        ['universal', der.universalString('a😀'), 'a😀'],
    ])('readString %s', (_, node, expected) => {
        expect(read.readString(node)).toBe(expected)
    })

    test('readString rejects non-strings and malformed content', () => {
        expect(() => read.readString(der.integer(1))).toThrow(Asn1ParseError)
        expect(() => read.readString(der.utf8String('x').implicit(12))).toThrow(
            Asn1ParseError,
        )
        expect(() => read.readString(hex('1e 01 00'))).toThrow(Asn1ParseError)
        expect(() => read.readString(hex('1c 02 00 00'))).toThrow(
            Asn1ParseError,
        )
        expect(() => read.readString(hex('0c 01 ff'))).toThrow()
    })

    test('readTime round-trips built times', () => {
        const date = new Date(Date.UTC(2026, 10, 11, 9, 5, 3))
        expect(read.readTime(der.utcTime(date))).toEqual(date)
        const precise = new Date(Date.UTC(2051, 1, 3, 4, 5, 6, 789))
        expect(read.readTime(der.generalizedTime(precise))).toEqual(precise)
    })

    test.each([
        [23, '500101000000Z', Date.UTC(1950, 0, 1)],
        [23, '491231235959Z', Date.UTC(2049, 11, 31, 23, 59, 59)],
        [23, '2601010000Z', Date.UTC(2026, 0, 1)],
        [23, '260101000000+0100', Date.UTC(2025, 11, 31, 23)],
        [24, '20260101120000-0230', Date.UTC(2026, 0, 1, 14, 30)],
        [24, '20260101120000.5Z', Date.UTC(2026, 0, 1, 12, 0, 0, 500)],
        [24, '2026010112Z', Date.UTC(2026, 0, 1, 12)],
    ])('readTime parses %i %s', (tag, text, expected) => {
        expect(read.readTime(time(tag, text)).getTime()).toBe(expected)
    })

    test.each([
        [23, '261301000000Z'],
        [23, '260230000000Z'],
        [23, '260101250000Z'],
        [23, '2601010000'],
        [24, '2026010112000Z'],
        [24, 'garbage'],
        [4, '20260101120000Z'],
    ])('readTime rejects %i %s', (tag, text) => {
        expect(() => read.readTime(time(tag, text))).toThrow(Asn1ParseError)
    })
})
