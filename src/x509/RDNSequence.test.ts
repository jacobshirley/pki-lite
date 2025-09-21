import { assert, describe, expect, test } from 'vitest'
import { RDNSequence } from './RDNSequence.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'

describe('RDNSequence', () => {
    test('can be created empty', () => {
        const rdnSequence = new RDNSequence()
        expect(rdnSequence).toBeInstanceOf(RDNSequence)
        expect(rdnSequence.length).toBe(0)
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
        expect(rdnSequence.length).toBe(1)
        expect(rdnSequence[0]).toBe(rdn)
    })

    test('can add RDNs after creation', () => {
        const rdnSequence = new RDNSequence()
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)

        rdnSequence.push(rdn)

        expect(rdnSequence.length).toBe(1)
        expect(rdnSequence[0]).toBe(rdn)
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

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        // Each item should be a Set (the ASN.1 representation of RelativeDistinguishedName)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Set)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Set)
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

        expect(rdnSequence.length).toBe(3)
        expect(rdnSequence[0]).toBe(rdn1)
        expect(rdnSequence[1]).toBe(rdn2)
        expect(rdnSequence[2]).toBe(rdn3)
    })

    test('can be parsed from ASN.1', () => {
        // Create ASN.1 structure for a DN like "CN=Test,OU=Unit"
        const asn1 = new asn1js.Sequence({
            value: [
                // First RDN - CN=Test
                new asn1js.Set({
                    value: [
                        new asn1js.Sequence({
                            value: [
                                new asn1js.ObjectIdentifier({
                                    value: '2.5.4.3',
                                }), // CN OID
                                new asn1js.PrintableString({ value: 'Test' }),
                            ],
                        }),
                    ],
                }),
                // Second RDN - OU=Unit
                new asn1js.Set({
                    value: [
                        new asn1js.Sequence({
                            value: [
                                new asn1js.ObjectIdentifier({
                                    value: '2.5.4.11',
                                }), // OU OID
                                new asn1js.PrintableString({ value: 'Unit' }),
                            ],
                        }),
                    ],
                }),
            ],
        })

        const rdnSequence = RDNSequence.fromAsn1(asn1)
        expect(rdnSequence).toBeInstanceOf(RDNSequence)
        expect(rdnSequence.length).toBe(2)

        // Check first RDN (CN=Test)
        expect(rdnSequence[0]).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdnSequence[0].length).toBe(1)
        expect(rdnSequence[0][0].type.toString()).toBe('2.5.4.3')
        expect(rdnSequence[0][0].shortName).toBe('CN')

        // Check second RDN (OU=Unit)
        expect(rdnSequence[1]).toBeInstanceOf(RelativeDistinguishedName)
        expect(rdnSequence[1].length).toBe(1)
        expect(rdnSequence[1][0].type.toString()).toBe('2.5.4.11')
        expect(rdnSequence[1][0].shortName).toBe('OU')
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a SEQUENCE
        const asn1 = new asn1js.Set({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })

        expect(() => RDNSequence.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE but got Set',
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
