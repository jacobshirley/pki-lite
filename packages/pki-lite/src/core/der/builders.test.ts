import { describe, expect, test } from 'vitest'
import * as asn1js from 'asn1js'
import { Asn1ParseError } from '../errors/Asn1ParseError.js'
import { Asn1Node } from './Asn1Node.js'
import * as der from './builders.js'

const toHex = (b: Uint8Array | ArrayBuffer) =>
    Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join(
        '',
    )
const ref = (block: asn1js.BaseBlock) => toHex(block.toBER(false))

describe('builders', () => {
    test('sequence, set and constructed skip absent fields', () => {
        const a = der.integer(1)
        expect(
            toHex(der.sequence([a, undefined, der.nullValue()]).encode()),
        ).toBe('3005020101' + '0500')
        expect(toHex(der.set([a]).encode())).toBe('3103020101')
        expect(toHex(der.constructed(3, [a]).encode())).toBe('a303020101')
    })

    test('boolean and null match asn1js', () => {
        expect(toHex(der.boolean(true).encode())).toBe('0101ff')
        expect(toHex(der.boolean(false).encode())).toBe('010100')
        expect(toHex(der.nullValue().encode())).toBe(ref(new asn1js.Null()))
    })

    test.each([
        0,
        1,
        127,
        128,
        255,
        256,
        -1,
        -128,
        -129,
        65535,
        Number.MAX_SAFE_INTEGER,
    ])('integer(%d) matches asn1js', (n) => {
        expect(toHex(der.integer(n).encode())).toBe(
            ref(new asn1js.Integer({ value: n })),
        )
        expect(toHex(der.integer(BigInt(n)).encode())).toBe(
            toHex(der.integer(n).encode()),
        )
    })

    test("integer(-(2^53 - 1)) is two's complement (asn1js gets this wrong)", () => {
        expect(toHex(der.integer(-Number.MAX_SAFE_INTEGER).encode())).toBe(
            '0207e0000000000001',
        )
    })

    test('integer from bytes is minimised', () => {
        expect(toHex(der.integer(new Uint8Array([0, 0, 0x7f])).encode())).toBe(
            '02017f',
        )
        expect(toHex(der.integer(new Uint8Array([0, 0x80])).encode())).toBe(
            '02020080',
        )
        expect(
            toHex(der.integer(new Uint8Array([0xff, 0xff, 0x80])).encode()),
        ).toBe('020180')
        expect(() => der.integer(new Uint8Array(0))).toThrow(Asn1ParseError)
        expect(() => der.integer(2 ** 60)).toThrow(Asn1ParseError)
    })

    test('unsignedInteger pads the high bit and strips leading zeros', () => {
        expect(
            toHex(der.unsignedInteger(new Uint8Array([0x80, 1])).encode()),
        ).toBe('0203008001')
        expect(
            toHex(der.unsignedInteger(new Uint8Array([0, 0, 5])).encode()),
        ).toBe('020105')
        expect(
            toHex(der.unsignedInteger(new Uint8Array([0, 0])).encode()),
        ).toBe('020100')
    })

    test('enumerated', () => {
        expect(toHex(der.enumerated(6).encode())).toBe(
            ref(new asn1js.Enumerated({ value: 6 })),
        )
    })

    test.each([
        '1.2.840.113549.1.1.11',
        '2.5.29.17',
        '0.9.2342.19200300.100.1.25',
        '2.999.3',
        '1.3.6.1.4.1.311.60.2.1.3',
    ])('oid(%s) matches asn1js', (oid) => {
        expect(toHex(der.oid(oid).encode())).toBe(
            ref(new asn1js.ObjectIdentifier({ value: oid })),
        )
    })

    test.each(['', '1', '3.1', '1.40', '1..2', 'a.b'])(
        'oid rejects %j',
        (oid) => {
            expect(() => der.oid(oid)).toThrow(Asn1ParseError)
        },
    )

    test('octet and bit strings', () => {
        const bytes = new Uint8Array([1, 2, 3])
        expect(toHex(der.octetString(bytes).encode())).toBe(
            ref(new asn1js.OctetString({ valueHex: bytes })),
        )
        expect(toHex(der.bitString(bytes).encode())).toBe(
            ref(new asn1js.BitString({ valueHex: bytes })),
        )
        expect(toHex(der.bitString(new Uint8Array([0x80]), 7).encode())).toBe(
            '03020780',
        )
        expect(() => der.bitString(bytes, 8)).toThrow(Asn1ParseError)
        expect(() => der.bitString(new Uint8Array(0), 1)).toThrow(
            Asn1ParseError,
        )
    })

    test('namedBits drops trailing zero bits', () => {
        // digitalSignature(0), keyEncipherment(2)
        expect(toHex(der.namedBits([true, false, true]).encode())).toBe(
            '030205a0',
        )
        expect(
            toHex(
                der
                    .namedBits([
                        false,
                        false,
                        false,
                        false,
                        false,
                        false,
                        false,
                        false,
                        true,
                    ])
                    .encode(),
            ),
        ).toBe('0303070080')
        expect(toHex(der.namedBits([false]).encode())).toBe('030100')
    })

    test('strings match asn1js', () => {
        expect(toHex(der.utf8String('héllo ✓').encode())).toBe(
            ref(new asn1js.Utf8String({ value: 'héllo ✓' })),
        )
        expect(toHex(der.printableString('Test CA').encode())).toBe(
            ref(new asn1js.PrintableString({ value: 'Test CA' })),
        )
        expect(toHex(der.ia5String('a@b.c').encode())).toBe(
            ref(new asn1js.IA5String({ value: 'a@b.c' })),
        )
        expect(toHex(der.bmpString('Zoë').encode())).toBe(
            ref(new asn1js.BmpString({ value: 'Zoë' })),
        )
        expect(toHex(der.universalString('a😀').encode())).toBe(
            '1c08' + '00000061' + '0001f600',
        )
        expect(toHex(der.teletexString('é').encode())).toBe('1401e9')
        expect(toHex(der.visibleString('hi').encode())).toBe('1a026869')
    })

    test('strings reject invalid characters', () => {
        expect(() => der.printableString('a@b')).toThrow(Asn1ParseError)
        expect(() => der.ia5String('é')).toThrow(Asn1ParseError)
        expect(() => der.visibleString('\n')).toThrow(Asn1ParseError)
        expect(() => der.bmpString('😀')).toThrow(Asn1ParseError)
        expect(() => der.teletexString('✓')).toThrow(Asn1ParseError)
    })

    test('utcTime', () => {
        const date = new Date(Date.UTC(2026, 10, 11, 9, 5, 3))
        expect(new TextDecoder().decode(der.utcTime(date).content)).toBe(
            '261111090503Z',
        )
        expect(toHex(der.utcTime(date).encode())).toBe(
            ref(new asn1js.UTCTime({ valueDate: date })),
        )
        expect(
            new TextDecoder().decode(
                der.utcTime(new Date(Date.UTC(1999, 0, 1))).content,
            ),
        ).toBe('990101000000Z')
        expect(() => der.utcTime(new Date(Date.UTC(2050, 0, 1)))).toThrow(
            Asn1ParseError,
        )
    })

    test('generalizedTime', () => {
        const text = (d: Date) =>
            new TextDecoder().decode(der.generalizedTime(d).content)
        expect(text(new Date(Date.UTC(2050, 0, 2, 3, 4, 5)))).toBe(
            '20500102030405Z',
        )
        expect(text(new Date(Date.UTC(2026, 0, 1, 0, 0, 0, 120)))).toBe(
            '20260101000000.12Z',
        )
        expect(text(new Date(Date.UTC(2026, 0, 1, 0, 0, 0, 5)))).toBe(
            '20260101000000.005Z',
        )
    })

    test('built nodes parse back to the same bytes', () => {
        const node = der.sequence([
            der.oid('1.2.3'),
            der.integer(-5).implicit(0),
            der.utf8String('x').explicit(1),
        ])
        expect(Asn1Node.parse(node.encode()).encode()).toEqual(node.encode())
    })
})
