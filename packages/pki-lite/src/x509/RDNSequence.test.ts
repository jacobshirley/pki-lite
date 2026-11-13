import { assert, describe, expect, test } from 'vitest'
import { RDNSequence } from './RDNSequence.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { Asn1Node, der, UniversalTag } from '../core/PkiBase.js'

describe('RDNSequence', () => {
    test('can be created empty', () => {
        const rdnSequence = new RDNSequence()
        expect(rdnSequence).toBeInstanceOf(RDNSequence)
        expect(rdnSequence.length).toEqual(0)
    })

    test('can be created with RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)
        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn)

        expect(rdnSequence).toBeInstanceOf(RDNSequence)
        expect(rdnSequence.length).toEqual(1)
        expect(rdnSequence[0]).toEqual(rdn)
    })

    test('can add RDNs after creation', () => {
        const rdnSequence = new RDNSequence()
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)

        rdnSequence.push(rdn)

        expect(rdnSequence.length).toEqual(1)
        expect(rdnSequence[0]).toEqual(rdn)
    })

    test('can be converted into ASN.1', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn1 = new RelativeDistinguishedName(cn)

        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const rdn2 = new RelativeDistinguishedName(ou)

        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn1, rdn2)

        const asn1 = rdnSequence.toAsn1()

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(2)

        // Each item should be a Set (the ASN.1 representation of RelativeDistinguishedName)
        expect(asn1.children[0].is(UniversalTag.Set)).toBe(true)
        expect(asn1.children[1].is(UniversalTag.Set)).toBe(true)
    })

    test('handles multiple RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn1 = new RelativeDistinguishedName(cn)

        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const rdn2 = new RelativeDistinguishedName(ou)

        const o = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Test Org',
        })
        const rdn3 = new RelativeDistinguishedName(o)

        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn1, rdn2, rdn3)

        expect(rdnSequence.length).toEqual(3)
        expect(rdnSequence[0]).toEqual(rdn1)
        expect(rdnSequence[1]).toEqual(rdn2)
        expect(rdnSequence[2]).toEqual(rdn3)
    })

    test('can be parsed from ASN.1', () => {
        // Create ASN.1 structure for a DN like "CN=Test,OU=Unit"
        const asn1 = der.sequence([
            // First RDN - CN=Test
            der.set([
                der.sequence([
                    der.oid('2.5.4.3'), // CN OID
                    der.printableString('Test'),
                ]),
            ]),
            // Second RDN - OU=Unit
            der.set([
                der.sequence([
                    der.oid('2.5.4.11'), // OU OID
                    der.printableString('Unit'),
                ]),
            ]),
        ])

        const rdnSequence = RDNSequence.fromAsn1(asn1)
        expect(rdnSequence).toBeInstanceOf(RDNSequence)
        expect(rdnSequence.length).toEqual(2)

        // Check first RDN (CN=Test)
        expect(rdnSequence[0]).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdnSequence[0].length).toEqual(1)
        expect(rdnSequence[0][0].type.toString()).toEqual('2.5.4.3')
        expect(rdnSequence[0][0].shortName).toEqual('CN')

        // Check second RDN (OU=Unit)
        expect(rdnSequence[1]).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdnSequence[1].length).toEqual(1)
        expect(rdnSequence[1][0].type.toString()).toEqual('2.5.4.11')
        expect(rdnSequence[1][0].shortName).toEqual('OU')
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a SEQUENCE
        const asn1 = der.set([der.octetString(new Uint8Array([1, 2, 3]))])

        expect(() => RDNSequence.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE but got SET',
        )
    })

    test('RDNSequence toString snapshot', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn1 = new RelativeDistinguishedName(cn)
        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn1)
        expect(rdnSequence.toString()).toMatchInlineSnapshot(`
          "[RDNSequence] SEQUENCE :
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.4.3
                PrintableString : 'Test Common Name'"
        `)
    })

    test('RDNSequence toString snapshot with multiple RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn1 = new RelativeDistinguishedName(cn)
        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const rdn2 = new RelativeDistinguishedName(ou)
        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn1, rdn2)
        expect(rdnSequence.toString()).toMatchInlineSnapshot(`
          "[RDNSequence] SEQUENCE :
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.4.3
                PrintableString : 'Test Common Name'
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.4.11
                PrintableString : 'Test Org Unit'"
        `)
    })

    test('RDNSequence toPem snapshot', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn1 = new RelativeDistinguishedName(cn)
        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn1)
        expect(rdnSequence.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN RDNSEQUENCE-----
          MBsxGTAXBgNVBAMTEFRlc3QgQ29tbW9uIE5hbWU=
          -----END RDNSEQUENCE-----"
        `)
    })

    test('RDNSequence toPem snapshot with multiple RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn1 = new RelativeDistinguishedName(cn)
        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Test Org Unit',
        })
        const rdn2 = new RelativeDistinguishedName(ou)
        const rdnSequence = new RDNSequence()
        rdnSequence.push(rdn1, rdn2)
        expect(rdnSequence.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN RDNSEQUENCE-----
          MDMxGTAXBgNVBAMTEFRlc3QgQ29tbW9uIE5hbWUxFjAUBgNVBAsTDVRlc3QgT3JnIFVuaXQ=
          -----END RDNSEQUENCE-----"
        `)
    })
})

const CN = '2.5.4.3'
const O = '2.5.4.10'
const C = '2.5.4.6'

/** A name from [type, value-block] pairs, one attribute per RDN */
const name = (...rdns: [string, Asn1Node][]) => {
    const sequence = new RDNSequence()
    for (const [type, value] of rdns) {
        const rdn = new RelativeDistinguishedName()
        rdn.push(new AttributeTypeAndValue({ type, value }))
        sequence.push(rdn)
    }
    return sequence
}
const printable = (value: string) => der.printableString(value)
const utf8 = (value: string) => der.utf8String(value)

describe('RDNSequence.matches / isWithin (RFC 5280 7.1)', () => {
    test('ignores case', () => {
        expect(
            name([CN, printable('Test CA')]).matches(
                name([CN, printable('TEST ca')]),
            ),
        ).toBe(true)
    })

    test('ignores leading, trailing and repeated whitespace', () => {
        expect(
            name([CN, printable('  Test   CA ')]).matches(
                name([CN, printable('Test CA')]),
            ),
        ).toBe(true)
    })

    test('treats PrintableString and UTF8String values alike', () => {
        expect(
            name([CN, printable('Test CA')]).matches(
                name([CN, utf8('test ca')]),
            ),
        ).toBe(true)
    })

    test('normalises Unicode (NFKC)', () => {
        // "ﬁ" (U+FB01, a ligature) is "fi" after compatibility normalisation
        expect(name([CN, utf8('ﬁle')]).matches(name([CN, utf8('file')]))).toBe(
            true,
        )
    })

    test('different values, types, RDN counts or order do not match', () => {
        expect(
            name([CN, utf8('Test CA')]).matches(name([CN, utf8('Test CA2')])),
        ).toBe(false)
        expect(name([CN, utf8('Acme')]).matches(name([O, utf8('Acme')]))).toBe(
            false,
        )
        expect(
            name([C, printable('US')]).matches(
                name([C, printable('US')], [CN, utf8('x')]),
            ),
        ).toBe(false)
        expect(
            name([C, printable('US')], [O, utf8('Acme')]).matches(
                name([O, utf8('Acme')], [C, printable('US')]),
            ),
        ).toBe(false)
    })

    test('compares non-string values by their encoding', () => {
        const value = (n: number) =>
            new AttributeTypeAndValue({
                type: CN,
                value: der.integer(n),
            })
        expect(value(1).matches(value(1))).toBe(true)
        expect(value(1).matches(value(2))).toBe(false)
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
        expect(rdn([CN, 'a'], [O, 'b']).matches(rdn([O, 'B'], [CN, 'A']))).toBe(
            true,
        )
    })

    test('isWithin checks for a prefix of RDNs', () => {
        const full = name(
            [C, printable('US')],
            [O, utf8('Acme')],
            [CN, utf8('Leaf')],
        )
        expect(
            full.isWithin(name([C, printable('us')], [O, utf8('ACME')])),
        ).toBe(true)
        expect(
            full.isWithin(name([C, printable('US')], [O, utf8('Other')])),
        ).toBe(false)
        expect(name([C, printable('US')]).isWithin(full)).toBe(false)
    })
})
