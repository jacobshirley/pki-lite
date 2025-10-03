import { describe, expect, it } from 'vitest'
import { SingleResponse } from './SingleResponse.js'
import { CertStatus } from './CertStatus.js'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Extension } from '../x509/Extension.js'

describe('SingleResponse', () => {
    it('should create a SingleResponse with minimum fields', () => {
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

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()

        const singleResponse = new SingleResponse({
            certID,
            certStatus,
            thisUpdate,
        })

        expect(singleResponse.certID).toEqual(certID)
        expect(singleResponse.certStatus).toEqual(certStatus)
        expect(singleResponse.thisUpdate.time).toEqual(thisUpdate)
        expect(singleResponse.nextUpdate?.time).toBeUndefined()
        expect(singleResponse.singleExtensions).toBeUndefined()
    })

    it('should create a SingleResponse with all fields', () => {
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

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const nextUpdate = new Date(thisUpdate.getTime() + 86400000) // 1 day later

        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })

        const singleResponse = new SingleResponse({
            certID,
            certStatus,
            thisUpdate,
            nextUpdate,
            singleExtensions: [extension],
        })

        expect(singleResponse.certID).toEqual(certID)
        expect(singleResponse.certStatus).toEqual(certStatus)
        expect(singleResponse.thisUpdate.time).toEqual(thisUpdate)
        expect(singleResponse.nextUpdate?.time).toEqual(nextUpdate)
        expect(singleResponse.singleExtensions).toHaveLength(1)
        expect(singleResponse.singleExtensions?.[0]).toEqual(extension)
    })

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
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()

        const original = new SingleResponse({ certID, certStatus, thisUpdate })
        const asn1 = original.toAsn1()
        const parsed = SingleResponse.fromAsn1(asn1)

        expect(parsed.certID.hashAlgorithm.algorithm).toEqual(
            hashAlgorithm.algorithm,
        )
        expect(parsed.certStatus.status).toEqual('good')
        expect(parsed.thisUpdate).not.toBeUndefined()
        expect(parsed.nextUpdate).toBeUndefined()
        expect(parsed.singleExtensions).toBeUndefined()
    })
})
