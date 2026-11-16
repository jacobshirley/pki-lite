import { OtherCertificateFormat } from './OtherCertificateFormat.js'
import { describe, test, expect } from 'vitest'
import { der, UniversalTag } from '../../core/PkiBase.js'
import { Any } from '../../asn1/Any.js'

describe('OtherCertificateFormat', () => {
    test('constructor sets the properties correctly', () => {
        const format = '1.2.840.113549.1.9.16.1.2' // example OID
        const cert = 'test certificate data'

        const otherCertFormat = new OtherCertificateFormat({
            otherCertFormat: format,
            otherCert: cert,
        })

        expect(otherCertFormat.otherCertFormat.toString()).toEqual(format)
        expect(otherCertFormat.otherCert.asString()).toEqual(cert)
    })

    test('toAsn1 creates the correct ASN.1 structure', () => {
        const format = '1.2.840.113549.1.9.16.1.2'
        const cert = 'test certificate data'

        const otherCertFormat = new OtherCertificateFormat({
            otherCertFormat: format,
            otherCert: cert,
        })
        const asn1 = otherCertFormat.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        const seq = asn1
        const value = seq.children
        expect(value.length).toEqual(2)

        const formatAsn1 = value[0]
        expect(formatAsn1.is(UniversalTag.ObjectIdentifier)).toBe(true)
        expect(der.readOid(formatAsn1)).toContain(format)

        const certAsn1 = value[1]
        expect(certAsn1.is(UniversalTag.PrintableString)).toBe(true)
        expect(der.readString(certAsn1)).toEqual(cert)
    })

    test('fromAsn1 parses the ASN.1 structure correctly', () => {
        const format = '1.2.840.113549.1.9.16.1.2'
        const cert = 'test certificate data'

        // Create an ASN.1 structure
        const asn1 = der.sequence([der.oid(format), der.printableString(cert)])

        const otherCertFormat = OtherCertificateFormat.fromAsn1(asn1)

        expect(otherCertFormat).toBeInstanceOf(OtherCertificateFormat)
        expect(otherCertFormat.otherCertFormat.toString()).toEqual(format)
        expect(otherCertFormat.otherCert.asString()).toEqual(cert)
    })

    test('fromAsn1 handles binary data correctly', () => {
        const format = '1.2.840.113549.1.9.16.1.2'
        const cert = new Uint8Array([1, 2, 3, 4, 5])

        // Create an ASN.1 structure
        const asn1 = der.sequence([der.oid(format), der.octetString(cert)])

        const otherCertFormat = OtherCertificateFormat.fromAsn1(asn1)

        expect(otherCertFormat).toBeInstanceOf(OtherCertificateFormat)
        expect(otherCertFormat.otherCertFormat.toString()).toEqual(format)
        expect(otherCertFormat.otherCert).toBeInstanceOf(Any)
    })

    test('fromAsn1 throws error for invalid structure', () => {
        // Not a Sequence
        const asn1NotSequence = der.integer(123)
        expect(() => OtherCertificateFormat.fromAsn1(asn1NotSequence)).toThrow(
            'expected SEQUENCE',
        )

        // Wrong number of elements
        const asn1WrongElements = der.sequence([der.oid('1.2.3.4')])
        expect(() =>
            OtherCertificateFormat.fromAsn1(asn1WrongElements),
        ).toThrow('expected 2 elements')

        // First element not an OID
        const asn1FirstNotOid = der.sequence([
            der.integer(123),
            der.printableString('test'),
        ])
        expect(() => OtherCertificateFormat.fromAsn1(asn1FirstNotOid)).toThrow(
            'expected OBJECT IDENTIFIER',
        )
    })
})
