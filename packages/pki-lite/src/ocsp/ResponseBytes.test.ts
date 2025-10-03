import { describe, expect, it } from 'vitest'
import { ResponseBytes } from './ResponseBytes.js'
import { OctetString } from '../asn1/OctetString.js'

describe('ResponseBytes', () => {
    it('should create a ResponseBytes', () => {
        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const response = new Uint8Array([1, 2, 3, 4, 5])

        const responseBytes = new ResponseBytes({ responseType, response })

        expect(responseBytes.responseType).toEqual(responseType)
        expect(responseBytes.response.bytes).toEqual(response)
    })

    it('should convert to ASN.1 and back', () => {
        const responseType = '1.3.6.1.5.5.7.48.1.1' // id-pkix-ocsp-basic
        const response = new Uint8Array([1, 2, 3, 4, 5])

        const original = new ResponseBytes({ responseType, response })
        const asn1 = original.toAsn1()
        const parsed = ResponseBytes.fromAsn1(asn1)

        expect(parsed.responseType).toEqual(responseType)
        expect(parsed.response.bytes).toEqual(response)
    })
})
