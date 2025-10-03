import * as asn1js from 'asn1js'
import { OtherCertificateFormat } from './OtherCertificateFormat.js'
import { describe, test, expect } from 'vitest'
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

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const seq = asn1 as asn1js.Sequence
        const value = seq.valueBlock.value
        expect(value.length).toEqual(2)

        const formatAsn1 = value[0] as asn1js.ObjectIdentifier
        expect(formatAsn1).toBeInstanceOf(asn1js.ObjectIdentifier)
        expect(formatAsn1.valueBlock.toString()).toContain(format)

        const certAsn1 = value[1] as asn1js.PrintableString
        expect(certAsn1).toBeInstanceOf(asn1js.PrintableString)
        expect((certAsn1.valueBlock as any).value).toEqual(cert)
    })

    test('fromAsn1 parses the ASN.1 structure correctly', () => {
        const format = '1.2.840.113549.1.9.16.1.2'
        const cert = 'test certificate data'

        // Create an ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: format }),
                new asn1js.PrintableString({ value: cert }),
            ],
        })

        const otherCertFormat = OtherCertificateFormat.fromAsn1(asn1)

        expect(otherCertFormat).toBeInstanceOf(OtherCertificateFormat)
        expect(otherCertFormat.otherCertFormat.toString()).toEqual(format)
        expect(otherCertFormat.otherCert.asString()).toEqual(cert)
    })

    test('fromAsn1 handles binary data correctly', () => {
        const format = '1.2.840.113549.1.9.16.1.2'
        const cert = new Uint8Array([1, 2, 3, 4, 5])

        // Create an ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: format }),
                new asn1js.OctetString({ valueHex: cert }),
            ],
        })

        const otherCertFormat = OtherCertificateFormat.fromAsn1(asn1)

        expect(otherCertFormat).toBeInstanceOf(OtherCertificateFormat)
        expect(otherCertFormat.otherCertFormat.toString()).toEqual(format)
        expect(otherCertFormat.otherCert).toBeInstanceOf(Any)
    })

    test('fromAsn1 throws error for invalid structure', () => {
        // Not a Sequence
        const asn1NotSequence = new asn1js.Integer({ value: 123 })
        expect(() => OtherCertificateFormat.fromAsn1(asn1NotSequence)).toThrow(
            'expected SEQUENCE',
        )

        // Wrong number of elements
        const asn1WrongElements = new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: '1.2.3.4' })],
        })
        expect(() =>
            OtherCertificateFormat.fromAsn1(asn1WrongElements),
        ).toThrow('expected 2 elements')

        // First element not an OID
        const asn1FirstNotOid = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 123 }),
                new asn1js.PrintableString({ value: 'test' }),
            ],
        })
        expect(() => OtherCertificateFormat.fromAsn1(asn1FirstNotOid)).toThrow(
            'expected OBJECT IDENTIFIER',
        )
    })
})
