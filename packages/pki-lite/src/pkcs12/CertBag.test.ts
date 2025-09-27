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
        expect(decoded.certId.value).toBe(certId)
        expect(Array.from(decoded.certValue.derBytes ?? [])).toEqual([
            1, 2, 3, 4,
        ])
    })
})
