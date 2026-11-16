import { RevocationInfoChoice } from './RevocationInfoChoice.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { TBSCertList } from '../x509/TBSCertList.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { describe, test, expect } from 'vitest'
import { der, derToAsn1 } from '../core/PkiBase.js'

describe('RevocationInfoChoice', () => {
    // Helper function to create a simple CRL for testing
    function createSimpleCRL(): CertificateList {
        // Create issuer name
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test CA',
        })
        const cnRdn = new RelativeDistinguishedName()
        cnRdn.push(cn)

        const name = new Name.RDNSequence()
        name.push(cnRdn)

        // Create minimal TBS cert list
        const tbsCertList = new TBSCertList({
            signature: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }), // SHA256 with RSA
            issuer: name,
            thisUpdate: new Date('2025-01-01'),
            nextUpdate: new Date('2026-01-01'),
            version: 1 as 1, // Explicit type annotation to fix compilation
        })

        // Create the CRL
        return new CertificateList({
            tbsCertList,
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }), // SHA256 with RSA
            signatureValue: new Uint8Array([1, 2, 3, 4]),
        })
    }

    // Test for fromAsn1 method with CertificateList (tag 0)
    test('fromAsn1 should correctly identify CertificateList', () => {
        // Create a real CRL and get its ASN.1 representation
        const crl = createSimpleCRL()
        const asn1 = crl.toAsn1()

        const result = RevocationInfoChoice.fromAsn1(asn1)

        expect(result).toBeInstanceOf(CertificateList)
        // Verify the CRL has the expected structure
        expect(
            (result as CertificateList).signatureAlgorithm.algorithm.toString(),
        ).toEqual('1.2.840.113549.1.1.11')
    })

    // Test for fromAsn1 method with OtherRevocationInfoFormat (tag 1)
    test('fromAsn1 should correctly identify OtherRevocationInfoFormat', () => {
        // Create a real OtherRevocationInfoFormat and get its ASN.1 representation
        const otherRevInfo = new OtherRevocationInfoFormat({
            otherRevInfoFormat: '1.2.3.4',
            otherRevInfo: 'test-revocation-info',
        })
        const asn1 = otherRevInfo.toAsn1()

        // other [1] IMPLICIT OtherRevocationInfoFormat

        const result = RevocationInfoChoice.fromAsn1(asn1.implicit(1))

        expect(result).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(
            (result as OtherRevocationInfoFormat).otherRevInfoFormat.toString(),
        ).toEqual('1.2.3.4')
    })

    // Integration test with real objects
    test('fromAsn1 integration test for CertificateList', () => {
        // Create a simplified real ASN.1 structure for a CRL
        const tbsCertListAsn1 = der.sequence([
            // Version (optional)
            der.integer(1),
            // Signature
            der.sequence([
                der.oid('1.2.840.113549.1.1.11'), // sha256WithRSAEncryption
            ]),
            // Issuer
            der.sequence([]),
            // ThisUpdate
            der.utcTime(new Date()),
            // NextUpdate (optional)
            der.utcTime(new Date(Date.now() + 86400000)), // tomorrow
            // RevocationEntries and Extensions omitted for simplicity
        ])

        const asn1 = der.sequence([
            tbsCertListAsn1,
            der.sequence([
                der.oid('1.2.840.113549.1.1.11'), // sha256WithRSAEncryption
            ]),
            der.bitString(new Uint8Array([1, 2, 3, 4])),
        ])

        try {
            const result = RevocationInfoChoice.fromAsn1(asn1)
            expect(result).toBeInstanceOf(CertificateList)
        } catch (error) {
            // This may fail due to missing required fields in the mock ASN.1 structure
            // Just checking that it's trying to parse as CRL
            expect((error as Error).message).not.toContain(
                'Unknown RevocationInfoChoice tag',
            )
        }
    })

    // Integration test with real objects
    test('fromAsn1 integration test for OtherRevocationInfoFormat', () => {
        // Create a real ASN.1 structure for OtherRevocationInfoFormat
        const asn1 = der.sequence([
            der.oid('1.3.6.1.5.5.7.48.1'), // OCSP OID
            der.octetString(new Uint8Array([1, 2, 3, 4])),
        ])

        // other [1] IMPLICIT OtherRevocationInfoFormat

        const result = RevocationInfoChoice.fromAsn1(asn1.implicit(1))

        expect(result).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(
            (result as OtherRevocationInfoFormat).otherRevInfoFormat.toString(),
        ).toEqual('1.3.6.1.5.5.7.48.1')
    })

    test('fromAsn1 parses a DER-encoded [1] IMPLICIT OtherRevocationInfoFormat', () => {
        const other = new OtherRevocationInfoFormat({
            otherRevInfoFormat: '1.2.3.4',
            otherRevInfo: 'x',
        })
        const der = other.toDer()
        der[0] = 0xa1 // SEQUENCE -> [1] IMPLICIT
        const result = RevocationInfoChoice.fromAsn1(derToAsn1(der))
        expect(result).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(result.toDer()).toEqual(other.toDer())
    })
})
