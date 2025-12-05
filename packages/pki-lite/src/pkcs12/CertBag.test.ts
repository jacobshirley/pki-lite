import { describe, it, expect } from 'vitest'
import { CertBag } from './CertBag.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Any } from '../asn1/Any.js'

describe('CertBag', () => {
    it('encodes and decodes X.509 cert bag', () => {
        const certId = '1.2.840.113549.1.9.22.1' // x509Certificate
        const certValue = new Uint8Array([1, 2, 3, 4])
        const bag = new CertBag({ certId, certValue })
        const der = bag.toDer()
        const decoded = CertBag.fromDer(der)
        expect(decoded.certId.value).toEqual(certId)
        // When invalid ASN.1 bytes are wrapped, they become an OctetString
        // So the derBytes now include the tag and length: [04 04 01 02 03 04]
        expect(Array.from(decoded.certValue.derBytes ?? [])).toEqual([
            4, 4, 1, 2, 3, 4,
        ])
    })
})
