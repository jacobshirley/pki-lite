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
import { der, UniversalTag } from '../../core/PkiBase.js'

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
            version: 2, // v3 (version=2)
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

        expect(info.version).toEqual(version)
        expect(info.certificate).toEqual(certificate)
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

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        // Check that structure has correct elements
        const items = asn1.children
        expect(items.length).toEqual(3)
        expect(items[0].is(UniversalTag.Integer)).toBe(true)

        // Check version value is correct
        const versionAsn1 = items[0]
        expect(der.readNumber(versionAsn1)).toEqual(version)

        // Check that attributes were converted to a Set
        expect(items[2].is(UniversalTag.Set)).toBe(true)
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

        expect(parsedInfo.version).toEqual(version)
        expect(parsedInfo.certificate).toBeInstanceOf(Certificate)
        expect(parsedInfo.attributes).toHaveLength(1)
        expect(parsedInfo.attributes[0]).toBeInstanceOf(Attribute)
        expect(parsedInfo.attributes[0].type.toString()).toEqual('1.2.3.4.5')
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        // Test with non-Sequence
        const invalidAsn1 = der.integer(1)
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Test with incorrect number of elements
        const invalidSequence = der.sequence([
            der.integer(1), // version
            der.sequence([]), // certificate
            // Missing attributes
        ])
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for version
        const invalidVersionType = der.sequence([
            der.bitString(new Uint8Array([1])), // Invalid type
            der.sequence([]), // certificate
            der.set([]), // attributes
        ])
        expect(() =>
            ExtendedCertificateInfo.fromAsn1(invalidVersionType),
        ).toThrow('Invalid ASN.1 structure: expected INTEGER for version')

        // Test with incorrect type for certificate
        const invalidCertType = der.sequence([
            der.integer(1), // version
            der.integer(1), // Invalid type
            der.set([]), // attributes
        ])
        expect(() => ExtendedCertificateInfo.fromAsn1(invalidCertType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for certificate',
        )

        // Test with incorrect type for attributes
        const invalidAttrsType = der.sequence([
            der.integer(1), // version
            der.sequence([]), // certificate
            der.integer(1), // Invalid type
        ])
        expect(() =>
            ExtendedCertificateInfo.fromAsn1(invalidAttrsType),
        ).toThrow('Invalid ASN.1 structure')
    })
})
