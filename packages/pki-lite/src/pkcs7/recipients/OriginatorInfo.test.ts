import { describe, expect, it } from 'vitest'
import { OriginatorInfo } from './OriginatorInfo.js'
import { CertificateSet } from '../../x509/CertificateSet.js'
import { Certificate } from '../../x509/Certificate.js'
import { asn1js } from '../../core/PkiBase.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('OriginatorInfo', () => {
    it('should create an empty OriginatorInfo', () => {
        const originatorInfo = new OriginatorInfo()

        // Check that both fields are undefined
        expect(originatorInfo.certs).toBeUndefined()
        expect(originatorInfo.crls).toBeUndefined()

        // Check that the ASN.1 encoding produces a SEQUENCE
        const asn1 = originatorInfo.toAsn1()
        expect(asn1 instanceof asn1js.Sequence).toEqual(true)
        expect((asn1 as any).valueBlock.value.length).toEqual(0)
    })

    it('should create an OriginatorInfo with certificates', () => {
        // Create a certificate from test fixture
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create a certificate set with one certificate
        const certSet = new CertificateSet(cert)

        // Create an OriginatorInfo with certificates
        const originatorInfo = new OriginatorInfo({ certs: certSet })

        // Check that the certificates field is populated
        expect(originatorInfo.certs).toBeDefined()
        expect(originatorInfo.certs?.length).toEqual(1)
        expect(originatorInfo.crls).toBeUndefined()

        // Check that the ASN.1 encoding is correct
        const asn1 = originatorInfo.toAsn1()
        expect(asn1 instanceof asn1js.Sequence).toEqual(true)
        expect((asn1 as any).valueBlock.value.length).toEqual(1)

        // Check that the first element is the certificates with correct tagging
        const certsAsn1 = (asn1 as any).valueBlock.value[0]
        expect(certsAsn1 instanceof asn1js.Constructed).toEqual(true)
        expect(certsAsn1.idBlock.tagClass).toEqual(3) // CONTEXT_SPECIFIC
        expect(certsAsn1.idBlock.tagNumber).toEqual(0) // [0]
    })

    it('should decode an OriginatorInfo from ASN.1', () => {
        // Create a certificate from test fixture
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create a certificate set with one certificate
        const certSet = new CertificateSet(cert)

        // Create an OriginatorInfo with certificates
        const originalInfo = new OriginatorInfo({ certs: certSet })

        // Encode to ASN.1
        const asn1 = originalInfo.toAsn1()

        // Decode back
        const decodedInfo = OriginatorInfo.fromAsn1(asn1)

        // Check that the decoded info has the certificates
        expect(decodedInfo.certs).toBeDefined()
        expect(decodedInfo.certs?.length).toEqual(1)
        expect(decodedInfo.crls).toBeUndefined()
    })

    it('should throw when trying to decode from an invalid ASN.1 structure', () => {
        // Try to decode from a non-Sequence ASN.1 structure
        const invalidAsn1 = new asn1js.Set()
        expect(() => OriginatorInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for OriginatorInfo',
        )
    })

    it('should correctly handle the absence of both certs and crls', () => {
        const originatorInfo = new OriginatorInfo()

        // Check that both fields are undefined
        expect(originatorInfo.certs).toBeUndefined()
        expect(originatorInfo.crls).toBeUndefined()

        // Encode to ASN.1
        const asn1 = originatorInfo.toAsn1()

        // Decode back
        const decodedInfo = OriginatorInfo.fromAsn1(asn1)

        // Check that both fields are still undefined
        expect(decodedInfo.certs).toBeUndefined()
        expect(decodedInfo.crls).toBeUndefined()
    })
})
