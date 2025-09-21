import { describe, expect, it } from 'vitest'
import { RevocationInfoChoices } from './RevocationInfoChoices.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { asn1js } from '../core/PkiBase.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('RevocationInfoChoices', () => {
    it('should create an empty RevocationInfoChoices', () => {
        const revocationInfoChoices = new RevocationInfoChoices()
        expect(revocationInfoChoices.length).toBe(0)

        // Check that the ASN.1 encoding produces a SET
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(0)
    })

    it('should create RevocationInfoChoices with a CRL', () => {
        // Create a CRL from the test fixture
        const crl = CertificateList.fromDer(rsaSigningKeys.caCrl)

        // Create RevocationInfoChoices with one CRL
        const revocationInfoChoices = new RevocationInfoChoices(crl)
        expect(revocationInfoChoices.length).toBe(1)

        // Check that the ASN.1 encoding is correct
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(1)

        // Check that the item is a CRL
        expect(revocationInfoChoices[0] instanceof CertificateList).toBe(true)
    })

    it('should create RevocationInfoChoices with OtherRevocationInfoFormat', () => {
        // Create an OtherRevocationInfoFormat instance
        const otherRevInfoFormat = '1.3.6.1.5.5.7.16.2' // OCSP response OID
        const otherRevInfo = new Uint8Array([1, 2, 3, 4, 5]) // Mock OCSP response data
        const otherFormat = new OtherRevocationInfoFormat({
            otherRevInfoFormat,
            otherRevInfo,
        })

        // Create RevocationInfoChoices with OtherRevocationInfoFormat
        const revocationInfoChoices = new RevocationInfoChoices(otherFormat)
        expect(revocationInfoChoices.length).toBe(1)

        // Check that the ASN.1 encoding is correct
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(1)

        // Check that the item is tagged as OtherRevocationInfoFormat [1]
        const firstItem = (asn1 as any).valueBlock.value[0]
        expect(firstItem.idBlock.tagClass).toBe(3) // CONTEXT_SPECIFIC
        expect(firstItem.idBlock.tagNumber).toBe(1) // [1]
    })

    it('should decode RevocationInfoChoices from ASN.1', () => {
        // Create a CRL from the test fixture
        const crl = CertificateList.fromDer(rsaSigningKeys.caCrl)

        // Create RevocationInfoChoices with one CRL
        const originalChoices = new RevocationInfoChoices(crl)

        // Encode to ASN.1
        const asn1 = originalChoices.toAsn1()

        // Decode back
        const decodedChoices = RevocationInfoChoices.fromAsn1(asn1)

        // Check that the decoded choices have the same count
        expect(decodedChoices.length).toBe(originalChoices.length)

        // Check that the item is a CRL
        expect(decodedChoices[0] instanceof CertificateList).toBe(true)
    })

    it('should handle multiple revocation info choices', () => {
        // Create a CRL from the test fixture
        const crl = CertificateList.fromDer(rsaSigningKeys.caCrl)

        // Create an OtherRevocationInfoFormat instance
        const otherRevInfoFormat = '1.3.6.1.5.5.7.16.2' // OCSP response OID
        const otherRevInfo = new Uint8Array([1, 2, 3, 4, 5]) // Mock OCSP response data
        const otherFormat = new OtherRevocationInfoFormat({
            otherRevInfoFormat,
            otherRevInfo,
        })

        // Create RevocationInfoChoices with both types
        const revocationInfoChoices = new RevocationInfoChoices(
            crl,
            otherFormat,
        )
        expect(revocationInfoChoices.length).toBe(2)

        // Check that the ASN.1 encoding is correct
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1 instanceof asn1js.Set).toBe(true)
        expect((asn1 as any).valueBlock.value.length).toBe(2)

        // Check that the second item is tagged as OtherRevocationInfoFormat [1]
        const secondItem = (asn1 as any).valueBlock.value[1]
        expect(secondItem.idBlock.tagClass).toBe(3) // CONTEXT_SPECIFIC
        expect(secondItem.idBlock.tagNumber).toBe(1) // [1]

        // Decode back
        const decodedChoices = RevocationInfoChoices.fromAsn1(asn1)
        expect(decodedChoices.length).toBe(2)
        expect(decodedChoices[0] instanceof CertificateList).toBe(true)
        expect(decodedChoices[1] instanceof OtherRevocationInfoFormat).toBe(
            true,
        )
    })

    it('should throw when trying to decode from an invalid ASN.1 structure', () => {
        // Try to decode from a non-Set ASN.1 structure
        const invalidAsn1 = new asn1js.Sequence()
        expect(() => RevocationInfoChoices.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Set for RevocationInfoChoices',
        )
    })
})
