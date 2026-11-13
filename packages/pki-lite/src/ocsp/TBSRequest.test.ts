import { describe, expect, it } from 'vitest'
import { TBSRequest } from './TBSRequest.js'
import { Request } from './Request.js'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Certificate } from '../x509/Certificate.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'
import { Extension } from '../x509/Extension.js'
import { Name } from '../x509/Name.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { der, UniversalTag } from '../core/PkiBase.js'

describe('TBSRequest', () => {
    const createTestRequest = () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({
            bytes: new Uint8Array([1, 2, 3, 4]),
        })
        const issuerKeyHash = new OctetString({
            bytes: new Uint8Array([5, 6, 7, 8]),
        })
        const serialNumber = new Uint8Array([9, 10, 11, 12])
        const certID = new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })
        return new Request({ reqCert: certID })
    }

    it('should create a TBSRequest with required fields only', () => {
        const request = createTestRequest()
        const tbsRequest = new TBSRequest({
            requestList: [request],
        })

        expect(tbsRequest.version).toEqual(0) // v1 is default
        expect(tbsRequest.requestorName).toBeUndefined()
        expect(tbsRequest.requestList).toHaveLength(1)
        expect(tbsRequest.requestList[0]).toEqual(request)
        expect(tbsRequest.requestExtensions).toBeUndefined()
    })

    it('should create a TBSRequest with all fields', () => {
        const request = createTestRequest()
        const requestorName = RDNSequence.fromAsn1(new RDNSequence().toAsn1())
        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })
        const tbsRequest = new TBSRequest({
            requestList: [request],
            version: 1,
            requestorName,
            requestExtensions: [extension],
        })

        expect(tbsRequest.version).toEqual(1)
        expect(tbsRequest.requestorName).toEqual(requestorName)
        expect(tbsRequest.requestList).toHaveLength(1)
        expect(tbsRequest.requestList[0]).toEqual(request)
        expect(tbsRequest.requestExtensions).toHaveLength(1)
        expect(tbsRequest.requestExtensions?.[0]).toEqual(extension)
    })

    it('should create a TBSRequest with multiple requests', () => {
        const request1 = createTestRequest()
        const request2 = createTestRequest()
        const tbsRequest = new TBSRequest({ requestList: [request1, request2] })

        expect(tbsRequest.requestList).toHaveLength(2)
        expect(tbsRequest.requestList[0]).toEqual(request1)
        expect(tbsRequest.requestList[1]).toEqual(request2)
    })

    it('should convert to ASN.1 and back with minimal fields', () => {
        const request = createTestRequest()
        const original = new TBSRequest({ requestList: [request] })
        const asn1 = original.toAsn1()
        const parsed = TBSRequest.fromAsn1(asn1)

        expect(parsed.version).toEqual(0) // v1
        expect(parsed.requestorName).toBeUndefined()
        expect(parsed.requestList).toHaveLength(1)
        expect(parsed.requestExtensions).toBeUndefined()
    })

    it('should convert to ASN.1 and back with non-default version', () => {
        const request = createTestRequest()
        const original = new TBSRequest({ requestList: [request], version: 1 }) // non-default version
        const asn1 = original.toAsn1()
        const parsed = TBSRequest.fromAsn1(asn1)

        expect(parsed.version).toEqual(1)
        expect(parsed.requestList).toHaveLength(1)
    })

    it('should convert to ASN.1 and back with requestor name', () => {
        const request = createTestRequest()
        const requestorName = RDNSequence.fromAsn1(new RDNSequence().toAsn1())
        const original = new TBSRequest({
            requestList: [request],
            version: 0,
            requestorName,
        })
        const asn1 = original.toAsn1()
        const parsed = TBSRequest.fromAsn1(asn1)

        expect(parsed.version).toEqual(0)
        expect(parsed.requestorName).toBeDefined()
        expect(parsed.requestList).toHaveLength(1)
    })

    it('should convert to ASN.1 and back with extensions', () => {
        const request = createTestRequest()
        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })
        const original = new TBSRequest({
            requestList: [request],
            version: 0,
            requestExtensions: [extension],
        })
        const asn1 = original.toAsn1()
        const parsed = TBSRequest.fromAsn1(asn1)

        expect(parsed.version).toEqual(0)
        expect(parsed.requestorName).toBeUndefined()
        expect(parsed.requestList).toHaveLength(1)
        expect(parsed.requestExtensions).toHaveLength(1)
        expect(parsed.requestExtensions?.[0].extnID.toString()).toEqual(
            '1.2.3.4',
        )
    })

    it('should convert to DER and back', () => {
        const request = createTestRequest()
        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })
        const original = new TBSRequest({
            requestList: [request],
            version: 0,
            requestExtensions: [extension],
        })
        const der = original.toDer()
        const parsed = TBSRequest.fromDer(der)

        expect(parsed.version).toEqual(0)
        expect(parsed.requestList).toHaveLength(1)
        expect(parsed.requestExtensions).toHaveLength(1)
    })

    it('should throw error on invalid ASN.1 structure', () => {
        const invalidAsn1 = der.integer(1) // not a SEQUENCE

        expect(() => TBSRequest.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error when missing requestList', () => {
        // Create an ASN.1 sequence with only version, no requestList
        const versionContainer = der.constructed(0, [der.integer(1)])

        const invalidAsn1 = der.sequence([versionContainer]) // Missing requestList

        expect(() => TBSRequest.fromAsn1(invalidAsn1)).toThrow(
            'Invalid TBSRequest: missing requestList',
        )
    })

    it('should handle empty extensions array', () => {
        const request = createTestRequest()
        const tbsRequest = new TBSRequest({
            requestList: [request],
            version: 0,
            requestExtensions: [],
        })

        expect(tbsRequest.requestExtensions).toEqual([])

        // When converting to ASN.1, empty extensions should not be included
        const asn1 = tbsRequest.toAsn1()
        const sequence = asn1
        expect(sequence.children).toHaveLength(1) // Only requestList
    })

    it('should not include default version in ASN.1', () => {
        const request = createTestRequest()
        const tbsRequest = new TBSRequest({
            requestList: [request],
            version: 0,
        }) // default version

        const asn1 = tbsRequest.toAsn1()
        const sequence = asn1

        // Should only contain the requestList, no version tag
        expect(sequence.children).toHaveLength(1)
        expect(sequence.children[0].is(UniversalTag.Sequence)).toBe(true)
    })

    it('should include non-default version in ASN.1', () => {
        const request = createTestRequest()
        const tbsRequest = new TBSRequest({
            requestList: [request],
            version: 1,
        }) // non-default version

        const asn1 = tbsRequest.toAsn1()
        const sequence = asn1

        // Should contain version tag and requestList
        expect(sequence.children).toHaveLength(2)

        const versionContainer = sequence.children[0]
        expect(versionContainer.tag).toEqual(0) // [0] tag
    })

    it('forCertificate identifies the issuer by its subject and key (RFC 6960 4.1.1)', async () => {
        // an issuer that is not self-signed, so its subject and issuer differ
        const issuer = Certificate.fromPem(rsaSigningKeys.certPem)
        const subject = Certificate.fromPem(rsaSigningKeys.caCertPem)
        const tbs = await TBSRequest.forCertificate({
            certificate: subject,
            issuerCertificate: issuer,
        })
        const expected = await CertID.forCertificate(
            issuer,
            subject,
            AlgorithmIdentifier.digestAlgorithm('SHA-256'),
        )
        expect(tbs.requestList[0].reqCert.toDer()).toEqual(expected.toDer())
    })
})
