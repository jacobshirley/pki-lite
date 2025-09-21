import { describe, expect, it } from 'vitest'
import { OCSPRequest } from './OCSPRequest.js'
import { CertID } from './CertID.js'
import { Request } from './Request.js'
import { TBSRequest } from './TBSRequest.js'
import { OCSPSignature } from './OCSPSignature.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Extension } from '../x509/Extension.js'
import { asn1js } from '../core/PkiBase.js'
import { Name } from '../x509/Name.js'
import { RDNSequence } from '../x509/RDNSequence.js'

describe('OCSPRequest', () => {
    it('should create an OCSPRequest with required fields', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
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
        const request = new Request({ reqCert: certID })
        const tbsRequest = new TBSRequest({ requestList: [request] })

        const ocspRequest = new OCSPRequest({ tbsRequest })

        expect(ocspRequest.tbsRequest).toBe(tbsRequest)
        expect(ocspRequest.optionalSignature).toBeUndefined()
    })

    it('should create an OCSPRequest with signature', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
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
        const request = new Request({ reqCert: certID })
        const tbsRequest = new TBSRequest({ requestList: [request] })

        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA-256 with RSA
        const signature = new Uint8Array([1, 2, 3, 4, 5])
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm: signatureAlgorithm,
            signature: signature,
        })

        const ocspRequest = new OCSPRequest({
            tbsRequest,
            optionalSignature: ocspSignature,
        })

        expect(ocspRequest.tbsRequest).toBe(tbsRequest)
        expect(ocspRequest.optionalSignature).toBe(ocspSignature)
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
            hashAlgorithm: hashAlgorithm,
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumber: serialNumber,
        })
        const request = new Request({ reqCert: certID })
        const tbsRequest = new TBSRequest({ requestList: [request] })

        const original = new OCSPRequest({ tbsRequest })
        const asn1 = original.toAsn1()
        const parsed = OCSPRequest.fromAsn1(asn1)

        expect(parsed.tbsRequest.version).toBe(0) // v1
        expect(parsed.tbsRequest.requestList).toHaveLength(1)
        expect(parsed.optionalSignature).toBeUndefined()
    })

    it('should convert to DER and back', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
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
        const request = new Request({ reqCert: certID })
        const tbsRequest = new TBSRequest({ requestList: [request] })

        const original = new OCSPRequest({ tbsRequest })
        const der = original.toDer()

        // Create a proper buffer for parsing
        const arrayBuffer = der.buffer.slice(
            der.byteOffset,
            der.byteOffset + der.byteLength,
        )
        const asn1 = asn1js.fromBER(arrayBuffer as ArrayBuffer).result
        const parsed = OCSPRequest.fromAsn1(asn1)

        expect(parsed.tbsRequest.version).toBe(0) // v1
        expect(parsed.tbsRequest.requestList).toHaveLength(1)
        expect(parsed.optionalSignature).toBeUndefined()
    })
})
