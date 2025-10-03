import { describe, expect, it } from 'vitest'
import { BasicOCSPResponse } from './BasicOCSPResponse.js'
import { ResponseData } from './ResponseData.js'
import { SingleResponse } from './SingleResponse.js'
import { CertStatus } from './CertStatus.js'
import { CertID } from './CertID.js'
import { ResponderID } from './ResponderID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'

describe('BasicOCSPResponse', () => {
    it('should create a BasicOCSPResponse with minimum fields', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
        const issuerKeyHash = new OctetString({ bytes: new Uint8Array([123]) })
        const serialNumber = new Uint8Array([9, 10, 11, 12])
        const certID = new CertID({
            hashAlgorithm: hashAlgorithm,
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumber: serialNumber,
        })

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID: certID,
            certStatus: certStatus,
            thisUpdate: thisUpdate,
        })

        const keyHash = new OctetString({ bytes: new Uint8Array([1, 2, 3, 4]) })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()
        const responseData = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
        })

        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA-256 with RSA
        const signatureValue = new Uint8Array([1, 2, 3, 4, 5])

        const basicResponse = new BasicOCSPResponse({
            tbsResponseData: responseData,
            signatureAlgorithm,
            signature: signatureValue,
        })

        expect(basicResponse.tbsResponseData).toEqual(responseData)
        expect(basicResponse.signatureAlgorithm).toEqual(signatureAlgorithm)
        expect(basicResponse.signature.bytes).toEqual(signatureValue)
        expect(basicResponse.certs).toBeUndefined()
    })

    // Skip certificate test because we need a proper certificate implementation

    it('should convert to ASN.1 and back', () => {
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
            hashAlgorithm: hashAlgorithm,
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumber: serialNumber,
        })

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID: certID,
            certStatus: certStatus,
            thisUpdate: thisUpdate,
        })

        const keyHash = new OctetString({ bytes: new Uint8Array([1, 2, 3, 4]) })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()
        const responseData = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
        })

        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA-256 with RSA
        const signatureValue = new Uint8Array([1, 2, 3, 4, 5])

        const original = new BasicOCSPResponse({
            tbsResponseData: responseData,
            signatureAlgorithm,
            signature: signatureValue,
        })
        const asn1 = original.toAsn1()
        const parsed = BasicOCSPResponse.fromAsn1(asn1)

        expect(parsed.tbsResponseData.version).toEqual(0) // v1
        expect(parsed.tbsResponseData.responderID).toBeInstanceOf(
            ResponderID.byKey,
        )
        expect(parsed.signatureAlgorithm.algorithm).toEqual(
            signatureAlgorithm.algorithm,
        )
        expect(parsed.signature.bytes).toEqual(signatureValue)
        expect(parsed.certs).toBeUndefined()
    })
})
