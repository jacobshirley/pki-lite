import * as asn1js from 'asn1js'
import { CertificateChoices } from './CertificateChoices.js'
import { Certificate } from './Certificate.js'
import { ExtendedCertificate } from './legacy/ExtendedCertificate.js'
import { AttributeCertificateV1 } from './attribute-certs/AttributeCertificateV1.js'
import { AttributeCertificate } from './attribute-certs/AttributeCertificate.js'
import { OtherCertificateFormat } from './legacy/OtherCertificateFormat.js'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('CertificateChoices', () => {
    // Setup mocks for fromAsn1 methods
    beforeEach(() => {
        vi.spyOn(Certificate, 'fromAsn1').mockImplementation(() => {
            return {} as Certificate
        })

        vi.spyOn(ExtendedCertificate, 'fromAsn1').mockImplementation(() => {
            //@ts-expect-error
            return new ExtendedCertificate({})
        })

        vi.spyOn(AttributeCertificateV1, 'fromAsn1').mockImplementation(() => {
            //@ts-expect-error
            return new AttributeCertificateV1({})
        })

        vi.spyOn(AttributeCertificate, 'fromAsn1').mockImplementation(() => {
            //@ts-expect-error
            return new AttributeCertificate({})
        })

        vi.spyOn(OtherCertificateFormat, 'fromAsn1').mockImplementation(() => {
            return new OtherCertificateFormat({
                otherCert: '1.2.3.4',
                otherCertFormat: 'test-cert',
            })
        })
    })

    afterEach(() => {
        vi.restoreAllMocks()
    })

    // Test for fromAsn1 method with Certificate
    test('fromAsn1 should correctly identify Certificate', () => {
        // Create a mock ASN.1 sequence with universal tag class
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [] }), // TBSCertificate
                new asn1js.Sequence({ value: [] }), // signatureAlgorithm
                new asn1js.BitString({
                    valueHex: new Uint8Array([1, 2, 3, 4]),
                }), // signatureValue
            ],
        })

        CertificateChoices.fromAsn1(asn1)

        expect(Certificate.fromAsn1).toHaveBeenCalledWith(asn1)
    })

    // Test for fromAsn1 method with ExtendedCertificate
    test('fromAsn1 should correctly identify ExtendedCertificate', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 0
        const asn1 = new asn1js.Sequence({
            value: [],
        })

        asn1.idBlock.tagClass = 3 // context-specific
        asn1.idBlock.tagNumber = 0 // ExtendedCertificate

        CertificateChoices.fromAsn1(asn1)

        expect(ExtendedCertificate.fromAsn1).toHaveBeenCalledWith(asn1)
    })

    // Test for fromAsn1 method with AttributeCertificateV1
    test('fromAsn1 should correctly identify AttributeCertificateV1', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 1
        const asn1 = new asn1js.Sequence({
            value: [],
        })

        asn1.idBlock.tagClass = 3 // context-specific
        asn1.idBlock.tagNumber = 1 // AttributeCertificateV1

        CertificateChoices.fromAsn1(asn1)

        expect(AttributeCertificateV1.fromAsn1).toHaveBeenCalledWith(asn1)
    })

    // Test for fromAsn1 method with AttributeCertificate
    test('fromAsn1 should correctly identify AttributeCertificate', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 2
        const asn1 = new asn1js.Sequence({
            value: [],
        })

        asn1.idBlock.tagClass = 3 // context-specific
        asn1.idBlock.tagNumber = 2 // AttributeCertificate

        CertificateChoices.fromAsn1(asn1)

        expect(AttributeCertificate.fromAsn1).toHaveBeenCalledWith(asn1)
    })

    // Test for fromAsn1 method with OtherCertificateFormat
    test('fromAsn1 should correctly identify OtherCertificateFormat', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 3
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.3.4' }),
                new asn1js.PrintableString({ value: 'test-cert' }),
            ],
        })

        asn1.idBlock.tagClass = 3 // context-specific
        asn1.idBlock.tagNumber = 3 // OtherCertificateFormat

        CertificateChoices.fromAsn1(asn1)

        expect(OtherCertificateFormat.fromAsn1).toHaveBeenCalledWith(asn1)
    })

    // Test for fromAsn1 method with unknown tag class
    test('fromAsn1 should throw error for unknown tag class', () => {
        // Create a mock ASN.1 structure with application tag class (2)
        const asn1 = new asn1js.Sequence({
            value: [],
        })

        asn1.idBlock.tagClass = 2 // application

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow(
            /Unknown CertificateChoices tag class/,
        )
    })

    // Test for fromAsn1 method with unknown tag number
    test('fromAsn1 should throw error for unknown tag number', () => {
        // Create a mock ASN.1 structure with context-specific tag class but unknown tag number
        const asn1 = new asn1js.Sequence({
            value: [],
        })

        asn1.idBlock.tagClass = 3 // context-specific
        asn1.idBlock.tagNumber = 4 // unknown tag number

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow(
            /Unknown CertificateChoices tag number/,
        )
    })
})
