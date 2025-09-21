import * as asn1js from 'asn1js'
import { ExtendedCertificateInfo } from './ExtendedCertificateInfo.js'
import { Certificate } from '../Certificate.js'
import { Attribute } from '../Attribute.js'
import { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'
import { Validity } from '../Validity.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Name } from '../Name.js'
import { RelativeDistinguishedName } from '../RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../AttributeTypeAndValue.js'
import { describe, test, expect } from 'vitest'

describe('ExtendedCertificateInfo', () => {
    // Helper function to create a real Certificate for testing
    function createTestCertificate(): Certificate {
        // Create subject and issuer names
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Certificate',
        })
        const cnRdn = new RelativeDistinguishedName()
        cnRdn.push(cn)

        const name = new Name.RDNSequence()
        name.push(cnRdn)

        // Create subject key info
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: new Uint8Array([1, 2, 3, 4, 5]),
        })

        // Create validity period
        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })

        // Create certificate information
        const tbsCertificate = new Certificate.TBSCertificate({
            issuer: name,
            subject: name,
            subjectPublicKeyInfo: spki,
            serialNumber: new Uint8Array([0x49, 0x96, 0x02, 0xd2]),
            validity,
            version: 2, // v3
            signature: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }),
        })

        // Create the certificate
        return new Certificate({
            tbsCertificate,
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }),
            signatureValue: new Uint8Array([10, 20, 30, 40, 50]),
        })
    }

    // Helper function to create test attributes
    function createTestAttributes(): Attribute[] {
        return [
            new Attribute({
                type: '1.2.3.4.5',
                values: ['test-attribute'],
            }),
        ]
    }

    test('constructor should initialize properties correctly', () => {
        const version = 1
        const certificate = createTestCertificate()
        const attributes = createTestAttributes()
        
        const info = new ExtendedCertificateInfo({
            version,
            certificate,
            attributes,
        })

        expect(info.version).toBe(version)
        expect(info.certificate).toBe(certificate)
        expect(info.attributes).toEqual(attributes)
    })

    test('toAsn1 should return correct ASN.1 structure', () => {
        const version = 1
        const certificate = createTestCertificate()
        const attributes = createTestAttributes()
        
        const info = new ExtendedCertificateInfo({
            version,
            certificate,
            attributes,
        })

        const asn1 = info.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // Check that structure has correct elements
        const valueBlock = (asn1 as asn1js.Sequence).valueBlock
        expect(valueBlock.value.length).toBe(3)
        expect(valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)

        // Check version value is correct
        const versionAsn1 = valueBlock.value[0] as asn1js.Integer
        expect(versionAsn1.valueBlock.valueDec).toBe(version)

        // Check that attributes were converted to a Set
        expect(valueBlock.value[2]).toBeInstanceOf(asn1js.Set)
    })

    test('fromAsn1 should parse ASN.1 structure correctly', () => {
        // Create a real ExtendedCertificateInfo object and convert it to ASN.1
        const version = 1
        const certificate = createTestCertificate()
        const attributes = createTestAttributes()
        
        const originalInfo = new ExtendedCertificateInfo({
            version,
            certificate,
            attributes,
        })
        
        // Convert to ASN.1 and back
        const asn1 = originalInfo.toAsn1()
        const parsedInfo = ExtendedCertificateInfo.fromAsn1(asn1)

        expect(parsedInfo.version).toBe(version)
        expect(parsedInfo.certificate).toBeInstanceOf(Certificate)
        expect(parsedInfo.attributes).toHaveLength(1)
        expect(parsedInfo.attributes[0]).toBeInstanceOf(Attribute)
        expect(parsedInfo.attributes[0].type.toString()).toBe('1.2.3.4.5')
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        // Test with non-Sequence
        const invalidAsn1 = new asn1js.Integer({ value: 1 })
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Test with incorrect number of elements
        const invalidSequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // version
                new asn1js.Sequence({ value: [] }), // certificate
                // Missing attributes
            ],
        })
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for version
        const invalidVersionType = new asn1js.Sequence({
            value: [
                new asn1js.BitString({ valueHex: new Uint8Array([1]) }), // Invalid type
                new asn1js.Sequence({ value: [] }), // certificate
                new asn1js.Set({ value: [] }), // attributes
            ],
        })
        expect(() =>
            ExtendedCertificateInfo.fromAsn1(invalidVersionType),
        ).toThrow('Invalid ASN.1 structure: expected INTEGER for version')

        // Test with incorrect type for certificate
        const invalidCertType = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // version
                new asn1js.Integer({ value: 1 }), // Invalid type
                new asn1js.Set({ value: [] }), // attributes
            ],
        })
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidCertType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for certificate',
        )

        // Test with incorrect type for attributes
        const invalidAttrsType = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // version
                new asn1js.Sequence({ value: [] }), // certificate
                new asn1js.Integer({ value: 1 }), // Invalid type
            ],
        })
        expect(() =>
            ExtendedCertificateInfo.fromAsn1(invalidAttrsType),
        ).toThrow(
            'Invalid ASN.1 structure: expected SET/CONSTRUCTED for Attributes but got Integer',
        )
    })
})
