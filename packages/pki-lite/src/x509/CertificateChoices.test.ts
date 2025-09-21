import * as asn1js from 'asn1js'
import { CertificateChoices } from './CertificateChoices.js'
import { Certificate } from './Certificate.js'
import { ExtendedCertificate } from './legacy/ExtendedCertificate.js'
import { AttributeCertificateV1 } from './attribute-certs/AttributeCertificateV1.js'
import { AttributeCertificate } from './attribute-certs/AttributeCertificate.js'
import { OtherCertificateFormat } from './legacy/OtherCertificateFormat.js'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('CertificateChoices', () => {
    // Setup test spies to verify routing logic without full parsing
    beforeEach(() => {
        vi.spyOn(Certificate, 'fromAsn1').mockImplementation(() => {
            throw new Error('Certificate.fromAsn1 called')
        })

        vi.spyOn(ExtendedCertificate, 'fromAsn1').mockImplementation(() => {
            throw new Error('ExtendedCertificate.fromAsn1 called')
        })

        vi.spyOn(AttributeCertificateV1, 'fromAsn1').mockImplementation(() => {
            throw new Error('AttributeCertificateV1.fromAsn1 called')
        })

        vi.spyOn(AttributeCertificate, 'fromAsn1').mockImplementation(() => {
            throw new Error('AttributeCertificate.fromAsn1 called')
        })

        vi.spyOn(OtherCertificateFormat, 'fromAsn1').mockImplementation(() => {
            throw new Error('OtherCertificateFormat.fromAsn1 called')
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

        // Certificate has universal tag class (1) and sequence tag number (16)
        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow('Certificate.fromAsn1 called')
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

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow('ExtendedCertificate.fromAsn1 called')
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

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow('AttributeCertificateV1.fromAsn1 called')
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

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow('AttributeCertificate.fromAsn1 called')
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

        expect(() => CertificateChoices.fromAsn1(asn1)).toThrow('OtherCertificateFormat.fromAsn1 called')
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
