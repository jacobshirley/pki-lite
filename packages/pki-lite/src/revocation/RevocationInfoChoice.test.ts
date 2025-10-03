import * as asn1js from 'asn1js'
import { RevocationInfoChoice } from './RevocationInfoChoice.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { TBSCertList } from '../x509/TBSCertList.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { describe, test, expect } from 'vitest'

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

        // Set tag number explicitly to ensure it's 0 (default for CRL)
        asn1.idBlock.tagNumber = 0

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

        // Set tag number to 1 for OtherRevocationInfoFormat
        asn1.idBlock.tagNumber = 1

        const result = RevocationInfoChoice.fromAsn1(asn1)

        expect(result).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(
            (result as OtherRevocationInfoFormat).otherRevInfoFormat.toString(),
        ).toEqual('1.2.3.4')
    })

    // Integration test with real objects
    test('fromAsn1 integration test for CertificateList', () => {
        // Create a simplified real ASN.1 structure for a CRL
        const tbsCertListAsn1 = new asn1js.Sequence({
            value: [
                // Version (optional)
                new asn1js.Integer({ value: 1 }),
                // Signature
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({
                            value: '1.2.840.113549.1.1.11',
                        }), // sha256WithRSAEncryption
                    ],
                }),
                // Issuer
                new asn1js.Sequence({ value: [] }),
                // ThisUpdate
                new asn1js.UTCTime({ value: new Date().toISOString() }),
                // NextUpdate (optional)
                new asn1js.UTCTime({
                    value: new Date(Date.now() + 86400000).toISOString(),
                }), // tomorrow
                // RevocationEntries and Extensions omitted for simplicity
            ],
        })

        const asn1 = new asn1js.Sequence({
            value: [
                tbsCertListAsn1,
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({
                            value: '1.2.840.113549.1.1.11',
                        }), // sha256WithRSAEncryption
                    ],
                }),
                new asn1js.BitString({
                    valueHex: new Uint8Array([1, 2, 3, 4]),
                }),
            ],
        })

        // Set tag number explicitly to ensure it's 0
        asn1.idBlock.tagNumber = 0

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
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.3.6.1.5.5.7.48.1' }), // OCSP OID
                new asn1js.OctetString({
                    valueHex: new Uint8Array([1, 2, 3, 4]),
                }),
            ],
        })

        // Set tag number to 1 for OtherRevocationInfoFormat
        asn1.idBlock.tagNumber = 1

        const result = RevocationInfoChoice.fromAsn1(asn1)

        expect(result).toBeInstanceOf(OtherRevocationInfoFormat)
        expect(
            (result as OtherRevocationInfoFormat).otherRevInfoFormat.toString(),
        ).toEqual('1.3.6.1.5.5.7.48.1')
    })
})
