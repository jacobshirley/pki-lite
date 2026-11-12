import { describe, expect, test } from 'vitest'
import { asn1js } from './PkiBase.js'
import {
    canonicalAttributeValue,
    nameWithin,
    namesMatch,
} from './NameMatching.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'

const CN = '2.5.4.3'
const O = '2.5.4.10'
const C = '2.5.4.6'

/** A name from [type, value-block] pairs, one attribute per RDN */
const name = (...rdns: [string, asn1js.BaseBlock][]) => {
    const sequence = new RDNSequence()
    for (const [type, value] of rdns) {
        const rdn = new RelativeDistinguishedName()
        rdn.push(new AttributeTypeAndValue({ type, value }))
        sequence.push(rdn)
    }
    return sequence
}
const printable = (value: string) => new asn1js.PrintableString({ value })
const utf8 = (value: string) => new asn1js.Utf8String({ value })

describe('NameMatching (RFC 5280 7.1)', () => {
    test('ignores case', () => {
        expect(
            namesMatch(
                name([CN, printable('Test CA')]),
                name([CN, printable('TEST ca')]),
            ),
        ).toBe(true)
    })

    test('ignores leading, trailing and repeated whitespace', () => {
        expect(
            namesMatch(
                name([CN, printable('  Test   CA ')]),
                name([CN, printable('Test CA')]),
            ),
        ).toBe(true)
    })

    test('treats PrintableString and UTF8String values alike', () => {
        expect(
            namesMatch(
                name([CN, printable('Test CA')]),
                name([CN, utf8('test ca')]),
            ),
        ).toBe(true)
    })

    test('normalises Unicode (NFKC)', () => {
        // "ﬁ" (U+FB01, a ligature) is "fi" after compatibility normalisation
        expect(
            namesMatch(name([CN, utf8('ﬁle')]), name([CN, utf8('file')])),
        ).toBe(true)
    })

    test('different values, types, RDN counts or order do not match', () => {
        expect(
            namesMatch(
                name([CN, utf8('Test CA')]),
                name([CN, utf8('Test CA2')]),
            ),
        ).toBe(false)
        expect(
            namesMatch(name([CN, utf8('Acme')]), name([O, utf8('Acme')])),
        ).toBe(false)
        expect(
            namesMatch(
                name([C, printable('US')]),
                name([C, printable('US')], [CN, utf8('x')]),
            ),
        ).toBe(false)
        expect(
            namesMatch(
                name([C, printable('US')], [O, utf8('Acme')]),
                name([O, utf8('Acme')], [C, printable('US')]),
            ),
        ).toBe(false)
    })

    test('compares non-string values by their encoding', () => {
        const a = new AttributeTypeAndValue({
            type: CN,
            value: new asn1js.Integer({ value: 1 }),
        })
        const b = new AttributeTypeAndValue({
            type: CN,
            value: new asn1js.Integer({ value: 2 }),
        })
        expect(canonicalAttributeValue(a)).toBe('d:020101')
        expect(canonicalAttributeValue(a)).not.toBe(canonicalAttributeValue(b))
    })

    test('multi-valued RDNs match whatever the order of their attributes', () => {
        const rdn = (...pairs: [string, string][]) => {
            const value = new RelativeDistinguishedName()
            for (const [type, v] of pairs)
                value.push(new AttributeTypeAndValue({ type, value: utf8(v) }))
            const sequence = new RDNSequence()
            sequence.push(value)
            return sequence
        }
        expect(
            namesMatch(rdn([CN, 'a'], [O, 'b']), rdn([O, 'B'], [CN, 'A'])),
        ).toBe(true)
    })

    test('nameWithin checks for a prefix of RDNs', () => {
        const full = name(
            [C, printable('US')],
            [O, utf8('Acme')],
            [CN, utf8('Leaf')],
        )
        expect(
            nameWithin(full, name([C, printable('us')], [O, utf8('ACME')])),
        ).toBe(true)
        expect(
            nameWithin(full, name([C, printable('US')], [O, utf8('Other')])),
        ).toBe(false)
        expect(nameWithin(name([C, printable('US')]), full)).toBe(false)
    })
})
