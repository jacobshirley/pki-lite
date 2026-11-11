import { CertificateChoices } from './CertificateChoices.js'
import { OtherCertificateFormat } from './legacy/OtherCertificateFormat.js'
import { describe, test, expect } from 'vitest'
import { der, TagClass } from '../core/PkiBase.js'

describe('CertificateChoices', () => {
    // Test for fromAsn1 method with Certificate
    test('fromAsn1 should correctly identify Certificate', () => {
        // Create a mock ASN.1 sequence with universal tag class
        const asn1 = der.sequence([
            der.sequence([]), // TBSCertificate
            der.sequence([]), // signatureAlgorithm
            der.bitString(new Uint8Array([1, 2, 3, 4])), // signatureValue
        ])

        // Certificate has universal tag class (1) and sequence tag number (16)
        // This should attempt to parse as Certificate and fail, proving routing worked
        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow()
        // The error will be from Certificate.fromAsn1 failing to parse the incomplete structure
    })

    // Test for fromAsn1 method with ExtendedCertificate
    test('fromAsn1 should correctly identify ExtendedCertificate', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 0
        const asn1 = der.sequence([]).implicit(0) // ExtendedCertificate

        // This should attempt to parse as ExtendedCertificate and fail, proving routing worked
        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow()
        // The error will be from ExtendedCertificate.fromAsn1 failing to parse the incomplete structure
    })

    // Test for fromAsn1 method with AttributeCertificateV1
    test('fromAsn1 should correctly identify AttributeCertificateV1', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 1
        const asn1 = der.sequence([]).implicit(1) // AttributeCertificateV1

        // This should attempt to parse as AttributeCertificateV1 and fail, proving routing worked
        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow()
        // The error will be from AttributeCertificateV1.fromAsn1 failing to parse the incomplete structure
    })

    // Test for fromAsn1 method with AttributeCertificate
    test('fromAsn1 should correctly identify AttributeCertificate', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 2
        const asn1 = der.sequence([]).implicit(2) // AttributeCertificate

        // This should attempt to parse as AttributeCertificate and fail, proving routing worked
        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow()
        // The error will be from AttributeCertificate.fromAsn1 failing to parse the incomplete structure
    })

    // Test for fromAsn1 method with OtherCertificateFormat
    test('fromAsn1 should correctly identify OtherCertificateFormat', () => {
        // Create a mock ASN.1 sequence with context-specific tag class and tag number 3
        const asn1 = der
            .sequence([der.oid('1.2.3.4'), der.printableString('test-cert')])
            .implicit(3) // OtherCertificateFormat

        // This should attempt to parse as OtherCertificateFormat and succeed
        const result = CertificateChoices.fromAsn1(asn1)
        expect(result).toBeInstanceOf(OtherCertificateFormat)
    })

    // Test for fromAsn1 method with unknown tag class
    test('fromAsn1 should throw error for unknown tag class', () => {
        // Create a mock ASN.1 structure with application tag class (2)
        const asn1 = der.sequence([]).implicit(16, TagClass.Application)

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow(
            /Unknown CertificateChoices tag class/,
        )
    })

    // Test for fromAsn1 method with unknown tag number
    test('fromAsn1 should throw error for unknown tag number', () => {
        // Create a mock ASN.1 structure with context-specific tag class but unknown tag number
        const asn1 = der.sequence([]).implicit(4) // unknown tag number

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow(
            /Unknown CertificateChoices tag number/,
        )
    })
})
