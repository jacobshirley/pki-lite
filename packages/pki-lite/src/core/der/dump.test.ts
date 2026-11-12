import { describe, expect, test } from 'vitest'
import { Asn1Node, TagClass, UniversalTag } from './Asn1Node.js'
import * as der from './builders.js'
import { dump } from './dump.js'

describe('dump', () => {
    test('renders constructed values with indented children', () => {
        const node = der.sequence([
            der.oid('1.2.840.113549.1.1.11'),
            der.nullValue(),
            der.set([der.integer(-5).explicit(0)]),
        ])
        expect(dump(node)).toBe(
            [
                'SEQUENCE :',
                '  OBJECT IDENTIFIER : 1.2.840.113549.1.1.11',
                '  NULL',
                '  SET :',
                '    [0] :',
                '      INTEGER : -5',
            ].join('\n'),
        )
    })

    test.each([
        [der.boolean(true), 'BOOLEAN: TRUE'],
        [der.boolean(false), 'BOOLEAN: FALSE'],
        [der.integer(2n ** 70n), 'INTEGER : 1180591620717411303424'],
        [der.enumerated(3), 'ENUMERATED : 3'],
        [der.octetString(new Uint8Array([1, 0xab])), 'OCTET STRING : 01ab'],
        [der.bitString(new Uint8Array([0xa0]), 5), 'BIT STRING : 101'],
        [der.printableString('John Doe'), "PrintableString : 'John Doe'"],
        [der.utf8String('✓'), "UTF8String : '✓'"],
        [der.bmpString('é'), "BmpString : 'é'"],
        [
            der.utcTime(new Date(Date.UTC(2024, 0, 1))),
            'UTCTime : 2024-01-01T00:00:00.000Z',
        ],
        [
            der.generalizedTime(new Date(Date.UTC(2050, 0, 1))),
            'GeneralizedTime : 2050-01-01T00:00:00.000Z',
        ],
        [der.octetString(new Uint8Array([7])).implicit(2), '[2] : 07'],
        [
            der.primitive(5, new Uint8Array([1]), TagClass.Application),
            '[APPLICATION 5] : 01',
        ],
        [der.primitive(99, new Uint8Array([1])), 'UNIVERSAL 99 : 01'],
    ])('renders %s', (node, expected) => {
        expect(dump(node)).toBe(expected)
    })

    test('falls back to hex for content it cannot decode', () => {
        const bad = new Asn1Node({
            tag: UniversalTag.UTCTime,
            content: new Uint8Array([0x41]),
        })
        expect(dump(bad)).toBe('UTCTime : 41')
        expect(
            dump(der.primitive(UniversalTag.Boolean, new Uint8Array(0))),
        ).toBe('BOOLEAN: ')
    })

    test('flattens a constructed (BER) string', () => {
        const node = Asn1Node.parse(
            new Uint8Array([
                0x24, 0x80, 0x04, 0x01, 0xaa, 0x04, 0x01, 0xbb, 0, 0,
            ]),
        )
        expect(dump(node)).toBe('OCTET STRING : aabb')
    })

    test('shows DER inside a parsed OCTET STRING or BIT STRING as a tree', () => {
        const inner = der.sequence([der.integer(5)])
        const parsed = Asn1Node.parse(
            der
                .sequence([
                    der.octetString(inner.encode()),
                    der.bitString(inner.encode()),
                ])
                .encode(),
        )
        expect(dump(parsed)).toBe(
            [
                'SEQUENCE :',
                '  OCTET STRING :',
                '    SEQUENCE :',
                '      INTEGER : 5',
                '  BIT STRING :',
                '    SEQUENCE :',
                '      INTEGER : 5',
            ].join('\n'),
        )
    })

    test('shows content that is not exactly one DER value, or a built node, as hex', () => {
        const inner = der.sequence([der.integer(5)]).encode()
        // built in code: shown as hex, like asn1js
        expect(dump(der.octetString(inner))).toBe('OCTET STRING : 3003020105')
        // trailing byte: not a single value
        const parsed = Asn1Node.parse(
            der.octetString(new Uint8Array([...inner, 0])).encode(),
        )
        expect(dump(parsed)).toBe('OCTET STRING : 300302010500')
        // a BIT STRING with unused bits is shown as bits
        expect(dump(Asn1Node.parse(der.bitString(inner, 1).encode()))).toBe(
            'BIT STRING : ' +
                '0011000000000011000000100000000100000101'.slice(0, -1),
        )
    })
})
