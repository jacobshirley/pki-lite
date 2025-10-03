import { assert, describe, expect, test } from 'vitest'
import { Name } from './Name.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'

describe('Name', () => {
    test('can be created empty', () => {
        const name = new Name.RDNSequence()
        expect(name.length).toEqual(0)
    })

    test('can be created with RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)
        const name = new Name.RDNSequence()
        name.push(rdn)

        expect(name.length).toEqual(1)
        expect(name[0]).toEqual(rdn)
    })

    test('can add RDNs after creation', () => {
        const name = new Name.RDNSequence()
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Common Name',
        })
        const rdn = new RelativeDistinguishedName(cn)

        name.push(rdn)

        expect(name.length).toEqual(1)
        expect(name[0]).toEqual(rdn)
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

        const name = new Name.RDNSequence()
        name.push(rdn1, rdn2)

        const asn1 = name.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)

        // Each item should be a Set (the ASN.1 representation of RelativeDistinguishedName)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Set)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Set)
    })

    test('can create a distinguished name', () => {
        // Create a typical X.509 Distinguished Name (DN)
        // Example: CN=John Doe, OU=Development, O=Example Corp, C=US
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'John Doe',
        })
        const rdnCN = new RelativeDistinguishedName(cn)

        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Development',
        })
        const rdnOU = new RelativeDistinguishedName(ou)

        const o = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Example Corp',
        })
        const rdnO = new RelativeDistinguishedName(o)

        const c = new AttributeTypeAndValue({ type: '2.5.4.6', value: 'US' })
        const rdnC = new RelativeDistinguishedName(c)

        const name = new Name.RDNSequence()
        name.push(rdnCN, rdnOU, rdnO, rdnC)

        expect(name.length).toEqual(4)

        // Check that the ASN.1 representation has the correct structure
        const asn1 = name.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(4)
    })

    test('toString snapshot', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'John Doe',
        })
        const rdnCN = new RelativeDistinguishedName(cn)
        const name = new Name.RDNSequence()
        name.push(rdnCN)
        expect(name.toString()).toMatchInlineSnapshot(`
          "[RDNSequence] SEQUENCE :
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.4.3
                PrintableString : 'John Doe'"
        `)
    })

    test('toString snapshot with multiple RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'John Doe',
        })
        const rdnCN = new RelativeDistinguishedName(cn)

        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Development',
        })
        const rdnOU = new RelativeDistinguishedName(ou)

        const name = new Name.RDNSequence()
        name.push(rdnCN, rdnOU)
        expect(name.toString()).toMatchInlineSnapshot(`
          "[RDNSequence] SEQUENCE :
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.4.3
                PrintableString : 'John Doe'
            SET :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.4.11
                PrintableString : 'Development'"
        `)
    })

    test('toPem snapshot', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'John Doe',
        })
        const rdnCN = new RelativeDistinguishedName(cn)
        const name = new Name.RDNSequence()
        name.push(rdnCN)
        expect(name.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN RDNSEQUENCE-----
          MBMxETAPBgNVBAMTCEpvaG4gRG9l
          -----END RDNSEQUENCE-----"
        `)
    })

    test('toPem snapshot with multiple RDNs', () => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'John Doe',
        })
        const rdnCN = new RelativeDistinguishedName(cn)

        const ou = new AttributeTypeAndValue({
            type: '2.5.4.11',
            value: 'Development',
        })
        const rdnOU = new RelativeDistinguishedName(ou)

        const name = new Name.RDNSequence()
        name.push(rdnCN, rdnOU)
        expect(name.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN RDNSEQUENCE-----
          MCkxETAPBgNVBAMTCEpvaG4gRG9lMRQwEgYDVQQLEwtEZXZlbG9wbWVudA==
          -----END RDNSEQUENCE-----"
        `)
    })
})
