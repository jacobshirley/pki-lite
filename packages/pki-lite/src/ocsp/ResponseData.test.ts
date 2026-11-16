import { describe, expect, it } from 'vitest'
import { ResponseData } from './ResponseData.js'
import { SingleResponse } from './SingleResponse.js'
import { CertStatus } from './CertStatus.js'
import { CertID } from './CertID.js'
import { ResponderID } from './ResponderID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Extension } from '../x509/Extension.js'
import { generalizedTimes } from '../../test-fixtures/generalizedTimes.js'

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

        expect(responseData.version).toEqual(0) // v1
        expect(responseData.responderID).toEqual(responderID)
        expect(responseData.producedAt).toEqual(producedAt)
        expect(responseData.responses).toHaveLength(1)
        expect(responseData.responses[0]).toEqual(singleResponse)
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

        expect(responseData.version).toEqual(0) // v1
        expect(responseData.responderID).toEqual(responderID)
        expect(responseData.producedAt).toEqual(producedAt)
        expect(responseData.responses).toHaveLength(1)
        expect(responseData.responses[0]).toEqual(singleResponse)
        expect(responseData.responseExtensions).toHaveLength(1)
        expect(responseData.responseExtensions?.[0]).toEqual(extension)
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

        expect(parsed.version).toEqual(0) // v1
        expect(parsed.responderID).toBeInstanceOf(ResponderID.byKey)
        expect(parsed.producedAt).not.toBeUndefined()
        expect(parsed.responses).toHaveLength(1)
        expect(parsed.responses[0].certStatus.status).toEqual('good')
        expect(parsed.responseExtensions).toBeUndefined()
    })

    it('encodes every time in whole seconds (rfc 6960, rfc 5280 4.1.2.5.2)', () => {
        const ms = (s: string) => new Date(`2026-11-16T12:00:${s}Z`)
        const certID = new CertID({
            hashAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.2.1',
            }),
            issuerNameHash: new OctetString({ bytes: new Uint8Array([1]) }),
            issuerKeyHash: new OctetString({ bytes: new Uint8Array([2]) }),
            serialNumber: new Uint8Array([3]),
        })
        const responseData = new ResponseData({
            responderID: new ResponderID.byKey(
                new OctetString({ bytes: new Uint8Array([4]) }),
            ),
            producedAt: ms('01.500'),
            responses: [
                new SingleResponse({
                    certID,
                    certStatus: CertStatus.createRevoked(ms('02.120')),
                    thisUpdate: ms('03.007'),
                    nextUpdate: ms('04.999'),
                }),
            ],
        })
        expect(generalizedTimes(responseData.toDer()).sort()).toEqual([
            '20261116120001Z',
            '20261116120002Z',
            '20261116120003Z',
            '20261116120004Z',
        ])
    })
})
