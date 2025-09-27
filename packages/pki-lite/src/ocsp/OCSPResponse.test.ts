import { describe, expect, it } from 'vitest'
import { OCSPResponse } from './OCSPResponse.js'
import { ResponseBytes } from './ResponseBytes.js'
import { OCSPResponseStatus } from './OCSPResponseStatus.js'
import { asn1js } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { BasicOCSPResponse } from './BasicOCSPResponse.js'
import { ResponseData } from './ResponseData.js'
import { Name } from '../x509/Name.js'

describe('OCSPResponse', () => {
    it('should create an OCSPResponse with successful status', () => {
        const responseStatus = OCSPResponseStatus.successful

        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const response = new Uint8Array([1, 2, 3, 4, 5])
        const responseBytes = new ResponseBytes({ responseType, response })

        const ocspResponse = new OCSPResponse({ responseStatus, responseBytes })

        expect(ocspResponse.responseStatus).toEqual(responseStatus)
        expect(ocspResponse.responseBytes).toEqual(responseBytes)
    })

    it('should create an OCSPResponse with error status and no responseBytes', () => {
        const responseStatus = OCSPResponseStatus.internalError

        const ocspResponse = new OCSPResponse({ responseStatus })

        expect(ocspResponse.responseStatus).toEqual(responseStatus)
        expect(ocspResponse.responseBytes).toBeUndefined()
    })

    it('should convert to ASN.1 and back for successful response', () => {
        const responseStatus = OCSPResponseStatus.successful

        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const response = new Uint8Array([1, 2, 3, 4, 5])
        const responseBytes = new ResponseBytes({ responseType, response })

        const original = new OCSPResponse({ responseStatus, responseBytes })
        const asn1 = original.toAsn1()
        const parsed = OCSPResponse.fromAsn1(asn1)

        expect(parsed.responseStatus).toEqual(responseStatus)
        expect(parsed.responseBytes?.responseType).toEqual(responseType)
        expect(parsed.responseBytes?.response.bytes).toEqual(response)
    })

    it('should convert to ASN.1 and back for error response', () => {
        const responseStatus = OCSPResponseStatus.internalError

        const original = new OCSPResponse({ responseStatus })
        const asn1 = original.toAsn1()
        const parsed = OCSPResponse.fromAsn1(asn1)

        expect(parsed.responseStatus).toEqual(responseStatus)
        expect(parsed.responseBytes).toBeUndefined()
    })

    it('should convert to DER and back', () => {
        const responseStatus = OCSPResponseStatus.successful

        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const response = new Uint8Array([1, 2, 3, 4, 5])
        const responseBytes = new ResponseBytes({ responseType, response })

        const original = new OCSPResponse({ responseStatus, responseBytes })
        const der = original.toDer()

        // Create a proper buffer for parsing
        const arrayBuffer = der.buffer.slice(
            der.byteOffset,
            der.byteOffset + der.byteLength,
        )
        const asn1 = asn1js.fromBER(arrayBuffer as ArrayBuffer).result
        const parsed = OCSPResponse.fromAsn1(asn1)

        expect(parsed.responseStatus).toEqual(responseStatus)
        expect(parsed.responseBytes?.responseType).toEqual(responseType)
        expect(parsed.responseBytes?.response.bytes).toEqual(response)
    })

    it('can extract BasicOCSPResponse from OCSPResponse', () => {
        const responseStatus = OCSPResponseStatus.successful
        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const responseBytes = new ResponseBytes({
            responseType,
            response: new BasicOCSPResponse({
                tbsResponseData: new ResponseData({
                    version: 1,
                    producedAt: new Date(),
                    responderID: Name.parse('CN=Test'),
                    responses: [],
                }),
                signatureAlgorithm: new AlgorithmIdentifier({
                    algorithm: '1.2.840.113549.1.1.11',
                }),
                signature: new Uint8Array([1, 2, 3]),
                certs: [],
            }),
        })

        const ocsp = new OCSPResponse({ responseStatus, responseBytes })
        const basic = ocsp.getBasicOCSPResponse()
        expect(basic).toBeDefined()
        expect(basic?.tbsResponseData.producedAt).toBeInstanceOf(Date)
        expect(basic?.signature.bytes).toEqual(new Uint8Array([1, 2, 3]))
    })
})
