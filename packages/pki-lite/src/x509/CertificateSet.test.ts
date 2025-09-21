import { describe, expect, it } from 'vitest'
import { CertificateSet } from './CertificateSet.js'
import { Certificate } from './Certificate.js'
import { asn1js } from '../core/PkiBase.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('CertificateSet', () => {
    it('should create an empty CertificateSet', () => {
        const certSet = new CertificateSet()
        expect(certSet.length).toBe(0)

        // Check that the ASN.1 encoding produces a SET
        const asn1 = certSet.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(0)
    })

    it('should create a CertificateSet with certificates', () => {
        // Create a certificate from test fixture
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create a certificate set with one certificate
        const certSet = new CertificateSet(cert)
        expect(certSet.length).toBe(1)

        // Check that the ASN.1 encoding is correct
        const asn1 = certSet.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(1)
    })

    it('should decode a CertificateSet from ASN.1', () => {
        // Create a certificate from test fixture
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create a certificate set and encode it
        const originalSet = new CertificateSet(cert)
        const asn1 = originalSet.toAsn1()

        // Decode it back
        const decodedSet = CertificateSet.fromAsn1(asn1)

        // Check that the decoded set has the same number of certificates
        expect(decodedSet.length).toBe(originalSet.length)

        // Check that both sets contain certificates
        for (const item of decodedSet) {
            expect(item instanceof Certificate).toBe(true)
        }
    })

    it('should handle multiple certificates in a set', () => {
        // Create a certificate from test fixture
        const cert1 = Certificate.fromPem(rsaSigningKeys.certPem)

        // For the second certificate, we'll use the same one since we're just testing the structure
        const cert2 = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create a certificate set with multiple certificates
        const certSet = new CertificateSet(cert1, cert2)
        expect(certSet.length).toBe(2)

        // Check that the ASN.1 encoding is correct
        const asn1 = certSet.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(2)

        // Decode it back
        const decodedSet = CertificateSet.fromAsn1(asn1)
        expect(decodedSet.length).toBe(2)
    })

    it('should throw when trying to decode from an invalid ASN.1 structure', () => {
        // Try to decode from a non-Set ASN.1 structure
        const invalidAsn1 = new asn1js.Sequence()
        expect(() => CertificateSet.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Set for CertificateSet',
        )
    })
})
