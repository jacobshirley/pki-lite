import { describe, expect, it } from 'vitest'
import { ResponseData } from './ResponseData.js'
import { SingleResponse } from './SingleResponse.js'
import { CertStatus } from './CertStatus.js'
import { CertID } from './CertID.js'
import { ResponderID } from './ResponderID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Extension } from '../x509/Extension.js'

describe('ResponseData', () => {
    it('should create a ResponseData with minimum fields', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({
            bytes: new Uint8Array([12, 3]),
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

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID,
            certStatus,
            thisUpdate,
        })

        const keyHash = new OctetString({ bytes: new Uint8Array([1, 2, 3, 4]) })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()

        const responseData = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
        })

        expect(responseData.version).toBe(0) // v1
        expect(responseData.responderID).toBe(responderID)
        expect(responseData.producedAt).toBe(producedAt)
        expect(responseData.responses).toHaveLength(1)
        expect(responseData.responses[0]).toBe(singleResponse)
        expect(responseData.responseExtensions).toBeUndefined()
    })

    it('should create a ResponseData with all fields', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
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

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID,
            certStatus,
            thisUpdate,
        })

        const keyHash = new OctetString({
            bytes: new Uint8Array([123, 123, 123]),
        })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()

        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })

        const responseData = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
            version: 0,
            responseExtensions: [extension],
        })

        expect(responseData.version).toBe(0) // v1
        expect(responseData.responderID).toBe(responderID)
        expect(responseData.producedAt).toBe(producedAt)
        expect(responseData.responses).toHaveLength(1)
        expect(responseData.responses[0]).toBe(singleResponse)
        expect(responseData.responseExtensions).toHaveLength(1)
        expect(responseData.responseExtensions?.[0]).toBe(extension)
    })

    it('should convert to ASN.1 and back', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
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

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID,
            certStatus,
            thisUpdate,
        })

        const keyHash = new OctetString({ bytes: new Uint8Array([123]) })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()

        const original = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
        })
        const asn1 = original.toAsn1()
        const parsed = ResponseData.fromAsn1(asn1)

        expect(parsed.version).toBe(0) // v1
        expect(parsed.responderID).toBeInstanceOf(ResponderID.byKey)
        expect(parsed.producedAt).not.toBeUndefined()
        expect(parsed.responses).toHaveLength(1)
        expect(parsed.responses[0].certStatus.status).toBe('good')
        expect(parsed.responseExtensions).toBeUndefined()
    })
})
