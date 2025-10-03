import { describe, expect, it } from 'vitest'
import { TBSRequest } from './TBSRequest.js'
import { Request } from './Request.js'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Extension } from '../x509/Extension.js'
import { Name } from '../x509/Name.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { asn1js } from '../core/PkiBase.js'

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
        const invalidAsn1 = {} as any

        expect(() => TBSRequest.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error when missing requestList', () => {
        // Create an ASN.1 sequence with only version, no requestList
        const versionContainer = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // CONTEXT-SPECIFIC
                tagNumber: 0, // [0]
            },
            value: [new asn1js.Integer({ value: 1 })],
        })

        const invalidAsn1 = new asn1js.Sequence({
            value: [versionContainer], // Missing requestList
        })

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
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value).toHaveLength(1) // Only requestList
    })

    it('should not include default version in ASN.1', () => {
        const request = createTestRequest()
        const tbsRequest = new TBSRequest({
            requestList: [request],
            version: 0,
        }) // default version

        const asn1 = tbsRequest.toAsn1()
        const sequence = asn1 as asn1js.Sequence

        // Should only contain the requestList, no version tag
        expect(sequence.valueBlock.value).toHaveLength(1)
        expect(sequence.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)
    })

    it('should include non-default version in ASN.1', () => {
        const request = createTestRequest()
        const tbsRequest = new TBSRequest({
            requestList: [request],
            version: 1,
        }) // non-default version

        const asn1 = tbsRequest.toAsn1()
        const sequence = asn1 as asn1js.Sequence

        // Should contain version tag and requestList
        expect(sequence.valueBlock.value).toHaveLength(2)

        const versionContainer = sequence.valueBlock
            .value[0] as asn1js.Constructed
        expect(versionContainer.idBlock.tagNumber).toEqual(0) // [0] tag
    })
})
