import { ExtendedCertificate } from './ExtendedCertificate.js'
import { ExtendedCertificateInfo } from './ExtendedCertificateInfo.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../Certificate.js'
import { Attribute } from '../Attribute.js'
import { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'
import { Validity } from '../Validity.js'
import { Name } from '../Name.js'
import { RelativeDistinguishedName } from '../RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../AttributeTypeAndValue.js'
import { describe, test, expect } from 'vitest'
import { der, UniversalTag } from '../../core/PkiBase.js'
import { BitString } from '../../asn1/BitString.js'

describe('ExtendedCertificate', () => {
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

    // Helper function to create test ExtendedCertificateInfo
    function createTestExtendedCertificateInfo(): ExtendedCertificateInfo {
        const certificate = createTestCertificate()
        const attributes = [
            new Attribute({
                type: '1.2.3.4.5',
                values: ['test-attribute'],
            }),
        ]

        return new ExtendedCertificateInfo({
            version: 1,
            certificate,
            attributes,
        })
    }

    test('constructor should initialize properties correctly', () => {
        const extendedCertificateInfo = createTestExtendedCertificateInfo()
        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const signature = new BitString({ value: new Uint8Array([1, 2, 3, 4]) })

        const extCert = new ExtendedCertificate({
            extendedCertificateInfo,
            signatureAlgorithm,
            signature,
        })

        expect(extCert.extendedCertificateInfo).toEqual(extendedCertificateInfo)
        expect(extCert.signatureAlgorithm).toEqual(signatureAlgorithm)
        expect(extCert.signature).toEqual(signature)
    })

    test('toAsn1 should return correct ASN.1 structure', () => {
        const extendedCertificateInfo = createTestExtendedCertificateInfo()
        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const signature = new BitString({ value: new Uint8Array([1, 2, 3, 4]) })

        const extCert = new ExtendedCertificate({
            extendedCertificateInfo,
            signatureAlgorithm,
            signature,
        })

        const asn1 = extCert.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        // Check that structure has correct elements
        const items = asn1.children
        expect(items.length).toEqual(3)
        expect(items[2].is(UniversalTag.BitString)).toBe(true)

        // Check BitString value matches signature
        const bitString = items[2]
        expect(der.readBitString(bitString).bytes).toEqual(signature.bytes)
    })

    test('fromAsn1 should parse ASN.1 structure correctly', () => {
        // Create a real ExtendedCertificate object and test roundtrip
        const extendedCertificateInfo = createTestExtendedCertificateInfo()
        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const signature = new BitString({ value: new Uint8Array([1, 2, 3, 4]) })

        const originalExtCert = new ExtendedCertificate({
            extendedCertificateInfo,
            signatureAlgorithm,
            signature,
        })

        // Convert to ASN.1 and back
        const asn1 = originalExtCert.toAsn1()
        const parsedExtCert = ExtendedCertificate.fromAsn1(asn1)

        expect(parsedExtCert.extendedCertificateInfo).toBeInstanceOf(
            ExtendedCertificateInfo,
        )
        expect(parsedExtCert.signatureAlgorithm).toBeInstanceOf(
            AlgorithmIdentifier,
        )
        expect(parsedExtCert.signatureAlgorithm.algorithm.toString()).toEqual(
            '1.2.840.113549.1.1.11',
        )
        expect(parsedExtCert.signature.bytes).toEqual(signature.bytes)
    })

    test('fromAsn1 throws error for invalid ASN.1 type', () => {
        const asn1 = der.integer(123)

        expect(() => ExtendedCertificate.fromAsn1(asn1)).toThrow(
            'expected SEQUENCE',
        )
    })

    test('fromAsn1 should throw error for ASN.1 structure with incorrect elements', () => {
        const mockSignatureBytes = new Uint8Array([1, 2, 3, 4])

        // Test with incorrect number of elements
        const invalidSequence = der.sequence([
            der.sequence([]), // extendedCertificateInfo
            der.sequence([]), // signatureAlgorithm
            // Missing signature
        ])
        expect(() => ExtendedCertificate.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )

        // Test with incorrect type for extendedCertificateInfo
        const invalidInfoType = der.sequence([
            der.integer(1), // Invalid type
            der.sequence([]), // signatureAlgorithm
            der.bitString(mockSignatureBytes), // signature
        ])
        expect(() => ExtendedCertificate.fromAsn1(invalidInfoType)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE for extendedCertificateInfo',
        )

        // Test with incorrect type for signatureAlgorithm
        const invalidAlgoType = der.sequence([
            der.sequence([]), // extendedCertificateInfo
            der.integer(1), // Invalid type
            der.bitString(mockSignatureBytes), // signature
        ])
        expect(() => ExtendedCertificate.fromAsn1(invalidAlgoType)).toThrow(
            'Invalid ASN.1 structure',
        )

        // Test with incorrect type for signature
        const invalidSigType = der.sequence([
            der.sequence([]), // extendedCertificateInfo
            der.sequence([]), // signatureAlgorithm
            der.integer(1), // Invalid type
        ])
        expect(() => ExtendedCertificate.fromAsn1(invalidSigType)).toThrow(
            'Invalid ASN.1 structure',
        )
    })
})
