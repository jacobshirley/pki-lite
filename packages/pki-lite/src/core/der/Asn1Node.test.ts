import { describe, expect, test } from 'vitest'
import * as asn1js from 'asn1js'
import { opensslCorpus } from '../../../test-fixtures/openssl-corpus/corpus.js'
import { Asn1ParseError } from '../errors/Asn1ParseError.js'
import { Asn1Node, TagClass, UniversalTag } from './Asn1Node.js'

const hex = (s: string) =>
    new Uint8Array(
        s
            .replace(/\s+/g, '')
            .match(/../g)!
            .map((b) => parseInt(b, 16)),
    )
const toHex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

/** Rebuilds a parsed tree from scratch so encode() can't reuse the parsed bytes. */
const rebuild = (node: Asn1Node): Asn1Node =>
    node.constructed
        ? new Asn1Node({
              tagClass: node.tagClass,
              tag: node.tag,
              children: node.children.map(rebuild),
          })
        : new Asn1Node({
              tagClass: node.tagClass,
              tag: node.tag,
              content: node.content,
          })

const children = (block: asn1js.BaseBlock): asn1js.BaseBlock[] =>
    (block?.valueBlock as { value?: asn1js.BaseBlock[] } | undefined)
        ?.value as asn1js.BaseBlock[]

const usesIndefiniteLength = (block: asn1js.BaseBlock): boolean =>
    !!block?.lenBlock?.isIndefiniteForm ||
    (Array.isArray(children(block)) &&
        children(block).some(usesIndefiniteLength))

describe('Asn1Node', () => {
    test('parses a primitive value', () => {
        const node = Asn1Node.parse(hex('02 02 01 00'))
        expect(node.tagClass).toBe(TagClass.Universal)
        expect(node.tag).toBe(UniversalTag.Integer)
        expect(node.constructed).toBe(false)
        expect(node.content).toEqual(hex('0100'))
        expect(node.describe()).toBe('INTEGER')
    })

    test('parses a constructed value', () => {
        const node = Asn1Node.parse(hex('30 06 02 01 05 01 01 ff'))
        expect(node.is(UniversalTag.Sequence)).toBe(true)
        expect(node.items()).toHaveLength(2)
        expect(node.children[1].is(UniversalTag.Boolean)).toBe(true)
    })

    test('parses long-form lengths', () => {
        const content = new Uint8Array(300).fill(7)
        const der = new Uint8Array([0x04, 0x82, 0x01, 0x2c, ...content])
        const node = Asn1Node.parse(der)
        expect(node.content).toEqual(content)
        expect(new Asn1Node({ tag: 4, content }).encode()).toEqual(der)
    })

    test('parses and encodes high tag numbers', () => {
        const der = hex('9f 81 00 01 aa')
        const node = Asn1Node.parse(der)
        expect(node.tagClass).toBe(TagClass.Context)
        expect(node.tag).toBe(128)
        expect(rebuild(node).encode()).toEqual(der)
    })

    test('parses indefinite lengths and re-encodes the original bytes', () => {
        const ber = hex('30 80 02 01 01 24 80 04 01 aa 04 01 bb 00 00 00 00')
        const node = Asn1Node.parse(ber)
        expect(node.children).toHaveLength(2)
        expect(node.children[1].bytes()).toEqual(hex('aabb'))
        expect(node.encode()).toEqual(ber)
        // A rebuilt tree is DER (definite lengths)
        expect(toHex(rebuild(node).encode())).toBe(
            '300b020101240604 01aa0401bb'.replace(/ /g, ''),
        )
    })

    test.each([
        ['empty input', ''],
        ['truncated length', '04 82 01'],
        ['length beyond data', '04 05 00'],
        ['trailing bytes', '05 00 00'],
        ['child overruns parent', '30 03 04 05 00'],
        ['primitive indefinite length', '04 80 00 00'],
        ['missing end-of-contents', '30 80 05 00'],
    ])('rejects %s', (_, input) => {
        expect(() =>
            Asn1Node.parse(hex(input || '00').subarray(input ? 0 : 1)),
        ).toThrow(Asn1ParseError)
    })

    test('rejects excessive nesting', () => {
        let der = hex('05 00')
        for (let i = 0; i < 100; i++)
            der = new Uint8Array([0x30, 0x80, ...der, 0, 0])
        expect(() => Asn1Node.parse(der)).toThrow(/nested too deeply/)
    })

    test('implicit and explicit tagging', () => {
        const int = new Asn1Node({ tag: 2, content: hex('05') })
        expect(int.implicit(1).encode()).toEqual(hex('81 01 05'))
        expect(int.explicit(1).encode()).toEqual(hex('a1 03 02 01 05'))
        const seq = Asn1Node.parse(hex('30 03 02 01 05'))
        const tagged = seq.implicit(0)
        expect(tagged.encode()).toEqual(hex('a0 03 02 01 05'))
        expect(tagged.isContext(0)).toBe(true)
        expect(tagged.retag(UniversalTag.Sequence).encode()).toEqual(
            seq.encode(),
        )
        // Re-tagging does not mutate the original
        expect(seq.is(UniversalTag.Sequence)).toBe(true)
    })

    test('expect and items throw descriptive errors', () => {
        const node = Asn1Node.parse(hex('02 01 00'))
        expect(node.expect(UniversalTag.Integer)).toBe(node)
        expect(() => node.expect(UniversalTag.Sequence, 'Certificate')).toThrow(
            'expected Certificate, got INTEGER',
        )
        expect(() => node.items()).toThrow(Asn1ParseError)
    })

    test('rejects nodes with both content and children', () => {
        expect(
            () =>
                new Asn1Node({
                    tag: 16,
                    content: new Uint8Array(0),
                    children: [],
                }),
        ).toThrow(Asn1ParseError)
    })

    test('toString dumps the tree', () => {
        const node = Asn1Node.parse(hex('30 05 a0 03 04 01 ff'))
        expect(node.toString()).toBe(
            'SEQUENCE :\n  [0] :\n    OCTET STRING : ff',
        )
    })

    describe('OpenSSL corpus', () => {
        const files = Object.entries(opensslCorpus).flatMap(([kind, entries]) =>
            Object.entries(entries).map(([name, data]) => [
                `${kind}/${name}`,
                data,
            ]),
        )

        test.each(files)('%s round-trips and matches asn1js', (_, data) => {
            const der = b64(data)
            const node = Asn1Node.parse(der)
            expect(node.encode()).toEqual(der)

            // A rebuilt tree is DER: identical to DER input, and the same tree as
            // asn1js sees for BER input
            const rebuilt = toHex(rebuild(node).encode())
            const reference = new Uint8Array(
                asn1js.fromBER(der).result.toBER(false),
            )
            expect(toHex(rebuild(Asn1Node.parse(reference)).encode())).toBe(
                rebuilt,
            )
            if (!usesIndefiniteLength(asn1js.fromBER(der).result)) {
                expect(rebuilt).toBe(toHex(der))
            }
        })
    })

    test('isParsed tells parsed nodes from built ones', () => {
        const built = new Asn1Node({ tag: 5, content: new Uint8Array(0) })
        expect(built.isParsed).toBe(false)
        built.encode() // caching the encoding does not make it parsed
        expect(built.isParsed).toBe(false)
        const parsed = Asn1Node.parse(hex('30 02 05 00'))
        expect(parsed.isParsed).toBe(true)
        expect(parsed.children[0].isParsed).toBe(true)
        expect(parsed.implicit(1).isParsed).toBe(false)
    })
})
