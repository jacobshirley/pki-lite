import { describe, expect, it } from 'vitest'
import { RevocationInfoChoices } from './RevocationInfoChoices.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { der, TagClass, UniversalTag } from '../core/PkiBase.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('RevocationInfoChoices', () => {
    it('should create an empty RevocationInfoChoices', () => {
        const revocationInfoChoices = new RevocationInfoChoices()
        expect(revocationInfoChoices.length).toEqual(0)

        // Check that the ASN.1 encoding produces a SET
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1.is(UniversalTag.Set)).toEqual(true)
        expect(asn1.children.length).toEqual(0)
    })

    it('should create RevocationInfoChoices with a CRL', () => {
        // Create a CRL from the test fixture
        const crl = CertificateList.fromDer(rsaSigningKeys.caCrl)

        // Create RevocationInfoChoices with one CRL
        const revocationInfoChoices = new RevocationInfoChoices(crl)
        expect(revocationInfoChoices.length).toEqual(1)

        // Check that the ASN.1 encoding is correct
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1.is(UniversalTag.Set)).toEqual(true)
        expect(asn1.children.length).toEqual(1)

        // Check that the item is a CRL
        expect(revocationInfoChoices[0] instanceof CertificateList).toEqual(
            true,
        )
    })

    it('should create RevocationInfoChoices with OtherRevocationInfoFormat', () => {
        // Create an OtherRevocationInfoFormat instance
        const otherRevInfoFormat = '1.3.6.1.5.5.7.16.2' // OCSP response OID
        const otherRevInfo = new Uint8Array([0x04, 0x03, 1, 2, 3]) // mock OCSP response data, as an OCTET STRING
        const otherFormat = new OtherRevocationInfoFormat({
            otherRevInfoFormat,
            otherRevInfo,
        })

        // Create RevocationInfoChoices with OtherRevocationInfoFormat
        const revocationInfoChoices = new RevocationInfoChoices(otherFormat)
        expect(revocationInfoChoices.length).toEqual(1)

        // Check that the ASN.1 encoding is correct
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1.is(UniversalTag.Set)).toEqual(true)
        expect(asn1.children.length).toEqual(1)

        // Check that the item is tagged as OtherRevocationInfoFormat [1]
        const firstItem = asn1.children[0]
        expect(firstItem.tagClass).toEqual(TagClass.Context) // CONTEXT_SPECIFIC
        expect(firstItem.tag).toEqual(1) // [1]
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
        expect(decodedChoices.length).toEqual(originalChoices.length)

        // Check that the item is a CRL
        expect(decodedChoices[0] instanceof CertificateList).toEqual(true)
    })

    it('should handle multiple revocation info choices', () => {
        // Create a CRL from the test fixture
        const crl = CertificateList.fromDer(rsaSigningKeys.caCrl)

        // Create an OtherRevocationInfoFormat instance
        const otherRevInfoFormat = '1.3.6.1.5.5.7.16.2' // OCSP response OID
        const otherRevInfo = new Uint8Array([0x04, 0x03, 1, 2, 3]) // mock OCSP response data, as an OCTET STRING
        const otherFormat = new OtherRevocationInfoFormat({
            otherRevInfoFormat,
            otherRevInfo,
        })

        // Create RevocationInfoChoices with both types
        const revocationInfoChoices = new RevocationInfoChoices(
            crl,
            otherFormat,
        )
        expect(revocationInfoChoices.length).toEqual(2)

        // Check that the ASN.1 encoding is correct
        const asn1 = revocationInfoChoices.toAsn1()
        expect(asn1.is(UniversalTag.Set)).toEqual(true)
        expect(asn1.children.length).toEqual(2)

        // Check that the second item is tagged as OtherRevocationInfoFormat [1]
        const secondItem = asn1.children[1]
        expect(secondItem.tagClass).toEqual(TagClass.Context) // CONTEXT_SPECIFIC
        expect(secondItem.tag).toEqual(1) // [1]

        // Decode back
        const decodedChoices = RevocationInfoChoices.fromAsn1(asn1)
        expect(decodedChoices.length).toEqual(2)
        expect(decodedChoices[0] instanceof CertificateList).toEqual(true)
        expect(decodedChoices[1] instanceof OtherRevocationInfoFormat).toEqual(
            true,
        )
    })

    it('should throw when trying to decode from an invalid ASN.1 structure', () => {
        // Try to decode from a non-Set ASN.1 structure
        const invalidAsn1 = der.sequence([])
        expect(() => RevocationInfoChoices.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Set for RevocationInfoChoices',
        )
    })
})
